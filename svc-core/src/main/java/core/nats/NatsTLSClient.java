package core.nats;

import core.handler.CaSecretManager;
import core.handler.CertificateManager;
import core.handler.CertificateUpdateCallbackIF;
import core.model.CaBundle;
import core.model.ServiceCoreIF;
import core.nats.NatsConsumerPoolManager.ConsumerDescriptor;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.nats.client.*;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.json.JsonObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.MessageDigest;

import java.time.Duration;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * NATS TLS Client with Proactive CA Rotation (refactored)
 *
 * Key improvements:
 * - Deterministic handshake for newly-created connections: expectedConnectionReady + expectedConnectionRef.
 * - Poll+flush fallback if CONNECTED event isn't observed.
 * - Per-consumer recreation retries with backoff to tolerate transient server timing races.
 * - Applied CA hash tracking so DISCONNECTED can trigger a fallback rotate only when necessary.
 * - Better logging (conn identity, full exception logging).
 */
public class NatsTLSClient implements CertificateUpdateCallbackIF
{
  private static final Logger LOGGER = LoggerFactory.getLogger(NatsTLSClient.class);

  private final List<CertificateUpdateCallbackIF> additionalCallbacks = new ArrayList<>();

  public static final String NATS_URLS = "NatsUrls";
  public static final String NATS_CA_CERT_PATH = "NatsCACertPath";
  public static final String NATS_CLIENT_CERT_PATH = "NatsClientCertPath";
  public static final String NATS_CLIENT_SECRET = "NatsClientSecret";

  private static final int  MAX_RECONNECTION_ATTEMPTS = 30;
  private static final long RETRY_DELAY_MS = 2000;

  // Config Parameters
  private String serviceId;
  private String natsUrls;
  private String natsCaPath;
  private String natsCertPath;
  private String clientSecretName;
  private String clientKeyPath;

  // Runtime vars
  private Vertx vertx;
  private volatile Connection natsConnection;
  private CertificateManager certificateManager;
  private CaSecretManager caSecretManager;
  private WorkerExecutor workerExecutor;

  // CA hash tracking for change detection
  private volatile String lastKnownCaContentHash = "";
  private volatile String appliedCaContentHash = "";

  // Generation tracking
  private final AtomicLong currentGeneration = new AtomicLong(1);

  // Set when handleCaBundleUpdate writes a new CA; cleared after recreate succeeds
  private final AtomicBoolean recreateInProgress       = new AtomicBoolean(false);
  private final AtomicLong    lastRecreateAttemptTime  = new AtomicLong(0);
  private static final long   MIN_RECREATE_INTERVAL_MS = 30000; // 30 seconds minimum between attempts

  // Expected-connection handshake (used during recreate)
  private volatile CompletableFuture<Void> expectedConnectionReady;
  private volatile Connection expectedConnectionRef;
  private volatile boolean    fullyInitialized = false;

  // circuit breaker for reconnection attempts
  private final AtomicInteger consecutiveRecreateFailures = new AtomicInteger(0);
  private static final int MAX_CONSECUTIVE_FAILURES = 3;

  // Pool managers
  private NatsProducerPoolManager producerPoolManager;
  private NatsConsumerPoolManager consumerPoolManager;
 
  // Kubernetes integration
  private KubernetesClient kubeClient;
  private String namespace;

  public NatsTLSClient(Vertx vertx, java.util.Map<String, String> config,
                      KubernetesClient kubeClient, String serviceId, String namespace)
    throws Exception
  {
    if (config == null || config.size() == 0)
    {
      throw new IllegalArgumentException("Config cannot be null or empty");
    }

    this.vertx = vertx;
    this.kubeClient = kubeClient;
    this.namespace = namespace;
    this.serviceId = serviceId;

    this.natsUrls = config.get(NATS_URLS);
    this.natsCaPath = config.get(NATS_CA_CERT_PATH);
    this.natsCertPath = config.get(NATS_CLIENT_CERT_PATH);
    this.clientSecretName = config.get(NATS_CLIENT_SECRET);

    LOGGER.info("*** NATS url = {}; caCertPath = {}; natsCertPath = {}; secret name = {}",
      natsUrls, natsCaPath, natsCertPath, clientSecretName);

    workerExecutor = vertx.createSharedWorkerExecutor("nats-client-worker", 2, 360000, TimeUnit.MILLISECONDS);
    this.caSecretManager = new CaSecretManager(kubeClient, namespace, serviceId);

    // Initialize CA file BEFORE certificate manager
    initializeWritableCaFile();

    this.certificateManager = new CertificateManager(kubeClient, namespace, clientSecretName,
      natsCaPath, natsCertPath, this);

    // Wait for certificates to be ready
    certificateManager.initialize().get();
    this.natsCertPath = certificateManager.getCertPath();
    this.clientKeyPath = certificateManager.getKeyPath();
    LOGGER.info("Certificate paths initialized - Cert: {}, Key: {}", natsCertPath, clientKeyPath);

    validateConfiguration();
    validateCertificateFiles();

    // Initialize CA hash
    initializeCaHash();

    waitForNatsReady();
    buildTlsConnectionWithListeners();

    this.producerPoolManager = new NatsProducerPoolManager(vertx, this);
    this.consumerPoolManager = new NatsConsumerPoolManager(vertx, this);

    this.addCertificateUpdateCallback(producerPoolManager);
    this.addCertificateUpdateCallback(consumerPoolManager);

    // At startup, mark applied CA hash as current
    appliedCaContentHash = lastKnownCaContentHash;
    fullyInitialized     = true;

    LOGGER.info("NATS client initialized - CA rotation uses proactive connection recreation");
  }

  /**
   * Build TLS connection with ConnectionListener for monitoring
   */
  private void buildTlsConnectionWithListeners() throws Exception
  {
    int maxRetries = 3;
    int retryDelay = 5000;

    for (int attempt = 1; attempt <= maxRetries; attempt++)
    {
      try
      {
        Options.Builder builder = new Options.Builder()
          .servers(natsUrls.split(","))
          .secure()
          .sslContext( createSSLContext() )  // Creates NEW SSLContext, reads new CA from disk
          .reconnectWait(Duration.ofSeconds(2))
          .maxReconnects(-1)
          .connectionTimeout(Duration.ofSeconds(15))
          .connectionListener(this::handleConnectionEvent)
          .errorListener(new ErrorListener()
          {
            @Override
            public void errorOccurred(Connection conn, String error)
            {
              LOGGER.warn("NATS error: {}", error);
            }

            @Override
            public void exceptionOccurred(Connection conn, Exception exp)
            {
              if (isCertificateRelatedError(exp))
              {
                LOGGER.info("Certificate error detected: {}", exp.getMessage());
                // Publish a TLS exception event on the event bus so services can react
                try {
                  if (vertx != null) {
                    JsonObject evt = new JsonObject()
                      .put("serviceId", serviceId)
                      .put("error", exp.getMessage() != null ? exp.getMessage() : "certificate error")
                      .put("timestamp", System.currentTimeMillis());
                    vertx.eventBus().publish("nats.tls.exception", evt);
                  }
                } 
                catch( Throwable t ) 
                {
                  LOGGER.debug("Failed to publish nats.tls.exception event: {}", t.getMessage());
                }
              }
              else
              {
                LOGGER.error("NATS exception: {}", exp == null ? "null" : exp.getMessage(), exp);
              }
            }
          });

        natsConnection = Nats.connect(builder.build());
        LOGGER.info("NATS connection established object={} identity={}", natsConnection, System.identityHashCode(natsConnection));
        return;
      }
      catch (Exception e)
      {
        LOGGER.error("Error building NATS connection (attempt {}/{}): {}", attempt, maxRetries, e.getMessage(), e);

        if (attempt == maxRetries)
        {
          throw new Exception("Failed to build NATS connection after " + maxRetries + " attempts", e);
        }
        Thread.sleep(retryDelay);
      }
    }
  }

  /**
   * Handle connection events - for monitoring and unexpected reconnects
   * We complete expectedConnectionReady only when CONNECTED is observed for the expectedConnectionRef.
   */
  private void handleConnectionEvent(Connection conn, ConnectionListener.Events type)
  {
    LOGGER.info("====================================================================");
    LOGGER.info("NatsTLSClient.handleConnectionEvent() - Event: {} connRef={}", 
      type, System.identityHashCode(conn));

    if (type == null) return;
    
    // Ignore events if recreation is in progress
    if (recreateInProgress.get() && type != ConnectionListener.Events.CONNECTED)
    {
      LOGGER.debug("Ignoring {} event during recreation", type);
      return;
    }

    try
    {
      switch (type)
      {
        case CONNECTED:
          LOGGER.info("🔌 NATS CONNECTED connRef={}", System.identityHashCode(conn));
          try 
          {
            Connection expected = expectedConnectionRef;
            CompletableFuture<Void> f = expectedConnectionReady;
            if (f != null && expected != null && conn == expected && !f.isDone()) {
              f.complete(null);
            }
          } 
          catch( Throwable t ) 
          {
            LOGGER.warn("Error completing connection handshake: {}", t.getMessage());
          }
          break;

        case DISCONNECTED:
          // Only trigger fallback if:
          // 1. This is our current connection
          // 2. We have a pending CA update
          // 3. Recreation is not already in progress
          // 4. We're not in cooldown period
          if (conn == this.natsConnection &&
              lastKnownCaContentHash != null &&
              !lastKnownCaContentHash.isEmpty() &&
              !lastKnownCaContentHash.equals(appliedCaContentHash))
          {
            long timeSinceLastAttempt = System.currentTimeMillis() - lastRecreateAttemptTime.get();
            
            if (timeSinceLastAttempt < MIN_RECREATE_INTERVAL_MS)
            {
              LOGGER.info("Throttling DISCONNECTED-triggered recreation ({}ms since last)", 
                timeSinceLastAttempt);
              return;
            }
            
            if (recreateInProgress.compareAndSet(false, true))
            {
              LOGGER.info("Pending CA detected on DISCONNECTED; scheduling recreation");
 
              // Notify services that a TLS/CA related condition was observed
              try 
              {
                if( vertx != null ) 
                {
                  JsonObject evt = new JsonObject()
                    .put("serviceId", serviceId)
                    .put("event", "disconnected_ca_mismatch")
                    .put("timestamp", System.currentTimeMillis());
                  vertx.eventBus().publish("nats.tls.exception", evt);
                }
              } 
              catch( Throwable t ) 
              {
                LOGGER.debug("Failed to publish nats.tls.exception on disconnect: {}", t.getMessage());
              }
              
              recreateConnectionWithNewCA().onComplete(ar -> 
              {
                recreateInProgress.set(false);
                if (ar.succeeded()) 
                {
                  LOGGER.info("DISCONNECTED-triggered recreation completed");
                } 
                else 
                {
                  LOGGER.error("DISCONNECTED-triggered recreation failed", ar.cause());
                }
              });
            }
          }
          break;

        case RECONNECTED:
          LOGGER.info("✅ NATS RECONNECTED connRef={}", System.identityHashCode(conn));
          break;

        default:
          LOGGER.debug("ℹ️  NATS event: {} connRef={}", type, System.identityHashCode(conn));
      }
    }
    catch (Throwable ex)
    {
      LOGGER.warn("Exception handling event {}: {}", type, ex.getMessage(), ex);
    }
  }

  private String shortHash(String h) {
    if (h == null) return "none";
    return h.length() > 8 ? h.substring(0,8) : h;
  }
  
  // ===== CA ROTATION METHOD =====


  private Future<Void> reconnectWithRetry( int attemptCount )
  {
    // Circuit breaker check
    if (consecutiveRecreateFailures.get() >= MAX_CONSECUTIVE_FAILURES)
    {
      long lastAttempt = lastRecreateAttemptTime.get();
      long timeSince = System.currentTimeMillis() - lastAttempt;
      if (timeSince < MIN_RECREATE_INTERVAL_MS * 10) // 5 minute cooldown
      {
        LOGGER.warn("Circuit breaker open - too many consecutive failures. Waiting for cooldown.");
        return Future.failedFuture("Circuit breaker open");
      }
      else
      {
        LOGGER.info("Circuit breaker cooldown complete - resetting failure count");
        consecutiveRecreateFailures.set(0);
      }
    }

    if( attemptCount >= MAX_RECONNECTION_ATTEMPTS )
    {
      consecutiveRecreateFailures.incrementAndGet();
      return Future.failedFuture( "Max attempts exceeded" );
    }

    long now = System.currentTimeMillis();
    long lastAttempt = lastRecreateAttemptTime.get();
    if (now - lastAttempt < MIN_RECREATE_INTERVAL_MS)
    {
      LOGGER.warn("Throttling reconnect attempt - too soon after last attempt");
      return Future.failedFuture("Reconnect throttled");
    }

    lastRecreateAttemptTime.set(now);

    return recreateConnectionWithNewCA().recover( err -> 
    {
      LOGGER.warn("recreateConnectionWithNewCA attempt {}/{} failed: {}", 
        attemptCount+1, MAX_RECONNECTION_ATTEMPTS, err.getMessage(), err);
      
      consecutiveRecreateFailures.incrementAndGet();
      
      if( attemptCount < MAX_RECONNECTION_ATTEMPTS - 1 )
      {
        Promise<Void> retry = Promise.promise();
        vertx.setTimer( RETRY_DELAY_MS * (attemptCount + 1), id -> {
          reconnectWithRetry( attemptCount + 1 ).onComplete( retry );
        });
        return retry.future();
      }
      return Future.failedFuture( err );
    }).onSuccess(v -> {
      // Reset failure counter on success
      consecutiveRecreateFailures.set(0);
    });
  } 
 
  private Future<Void> recreateConnectionWithNewCA()
  {
    return vertx.executeBlocking( () -> {
      LOGGER.info( "╔══════════════════════════════════════════════════════════╗" );
      LOGGER.info( "║ Safe-Fast CA Rotation Starting                           ║" );
      LOGGER.info( "╚══════════════════════════════════════════════════════════╝" );

      Connection oldConnection = natsConnection;
      long oldGeneration = currentGeneration.get();

      try
      {
        long startTime = System.currentTimeMillis();

        // Stop timers via the consumer pool manager (single canonical place)
        if( consumerPoolManager != null )
        {
          consumerPoolManager.stopAllPullTimersSync();
        }

        // Create new connection
        Options.Builder builder = new Options.Builder().servers( natsUrls.split( "," ) ).secure().sslContext( createSSLContext() ).connectionTimeout( Duration.ofSeconds( 3 ) ).maxReconnects( -1 );

        // Initialize expected-connection handshake BEFORE connecting so the
        // ConnectionListener can complete the future on CONNECTED.
        expectedConnectionReady = new CompletableFuture<>();
        expectedConnectionRef = null;

        Connection newConn = Nats.connect( builder.build() );

        // Mark the expected connection for the listener and the local reference
        expectedConnectionRef = newConn;
        this.natsConnection = newConn;

        LOGGER.info( "Created new connection identity={}", System.identityHashCode( newConn ) );

        // Quick verification (wait for listener to complete the handshake
        // future)
        try
        {
          expectedConnectionReady.get( 2, TimeUnit.SECONDS );
        }
        catch( TimeoutException te )
        {
          LOGGER.debug( "Using polling fallback for connection ready" );
          waitForConnectionReady( newConn, Duration.ofSeconds( 2 ) );
        }
        finally
        {
          // Clear handshake placeholders (avoid stale state)
          expectedConnectionRef = null;
          expectedConnectionReady = null;
        }

        // Single flush verification
        newConn.flush( Duration.ofSeconds( 1 ) );
        LOGGER.info( "✅ New connection verified" );

        // Update generation
        long newGeneration = currentGeneration.incrementAndGet();

        // Close old connection
        if( oldConnection != null && oldConnection != newConn )
        {
          try
          {
            if( oldConnection.getStatus() == Connection.Status.CONNECTED )
            {
              oldConnection.flush( Duration.ofSeconds( 1 ) );
            }
            oldConnection.close();
            LOGGER.info( "✅ Old connection closed" );
          }
          catch( Exception e )
          {
            LOGGER.warn( "Old connection close error: {}", e.getMessage() );
          }
        }

        // Trigger pool recreation
        vertx.runOnContext( v -> {
          recreatePoolsWithNewConnection( newConn, newGeneration );
        } );

        long elapsed = System.currentTimeMillis() - startTime;

        LOGGER.info( "══════════════════════════════════════════════════════════════════════════════════════" );
        LOGGER.info( "✅ Safe-Fast Rotation Complete (Gen: {})- Consumer Rotation Duration: {} ms", newGeneration, elapsed );
        LOGGER.info( "══════════════════════════════════════════════════════════════════════════════════════" );

        appliedCaContentHash = lastKnownCaContentHash;
        return null;

      }
      catch( Exception e )
      {
        LOGGER.error( "❌ Rotation failed", e );
        if( oldConnection != null )
        {
          this.natsConnection = oldConnection;
        }
        throw new RuntimeException( e );
      }
    } ).mapEmpty();
  }
  

  private void recreatePoolsWithNewConnection(Connection newConnection, long newGeneration)
  {
    if (!fullyInitialized)
    {
      LOGGER.warn("Skipping pool recreation - not fully initialized yet");
      return;
    }

    if( producerPoolManager == null || consumerPoolManager == null )
    {
      LOGGER.warn("Skipping pool recreation - pool managers not initialized");
      return;
    }
   
    LOGGER.info("♻️  Recreating pools with generation {}", newGeneration);

    try
    {
      // Just trigger the callbacks - they handle their own threading
      // Do NOT call these from inside a blocking operation
      producerPoolManager.onCertificateUpdated();
      consumerPoolManager.onCertificateUpdated();
      
      LOGGER.info("Pool migration callbacks triggered for generation {}", newGeneration);
    }
    catch (Exception e)
    {
      LOGGER.error("Error triggering pool recreation: {}", e.getMessage(), e);
      throw e;
    }
  }

  /**
   * Wait until connection reports CONNECTED status (with a timeout).
   * This helps avoid racing into subscriptions before the client+server are fully ready.
   */
  private void waitForConnectionReady(Connection conn, Duration timeout) {
    if (conn == null) return;
    long deadline = System.currentTimeMillis() + timeout.toMillis();
    try {
      while (System.currentTimeMillis() < deadline) {
        try {
          if (conn.getStatus() == Connection.Status.CONNECTED) {
            LOGGER.debug("Connection {} reports CONNECTED", System.identityHashCode(conn));
            return;
          }
        } catch (Throwable t) {
          // ignore and retry
        }
        Thread.sleep(100);
      }
      LOGGER.warn("Timeout waiting for connection to reach CONNECTED state; proceeding to flush fallback");
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
    }
  }

  /**
   * Try several short flush attempts (ms) - returns true on success.
   private boolean tryFlushWithRetries(Connection conn, int[] attemptsMs, Duration fallbackTimeout)
  {
    if (conn == null) return false;

    for (int ms : attemptsMs)
    {
      try
      {
        conn.flush(java.time.Duration.ofMillis(ms));
        LOGGER.debug("Flushed connection {} in {} ms", System.identityHashCode(conn), ms);
        return true;
      }
      catch (Throwable flushEx)
      {
        LOGGER.debug("Flush attempt {}ms failed for connection {}: {}", ms, System.identityHashCode(conn), flushEx.getMessage());
        try { Thread.sleep(20); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
      }
    }

    // final fallback try with provided fallbackTimeout
    try
    {
      conn.flush(fallbackTimeout);
      LOGGER.debug("Fallback flush succeeded for connection {}", System.identityHashCode(conn));
      return true;
    }
    catch (Throwable t)
    {
      LOGGER.warn("All flush attempts failed for connection {}: {}", System.identityHashCode(conn), t.getMessage(), t);
      return false;
    }
  }
*/

  // ===== SSL CONTEXT AND CERTIFICATE METHODS =====

  /**
   * Create SSL context for NATS TLS connection
   * Reads CA file from disk, so new invocations read new CA
   */
  private SSLContext createSSLContext() throws Exception
  {
    if (Security.getProvider("BC") == null)
    {
      Security.addProvider(new BouncyCastleProvider());
    }

    CertificateFactory cf = CertificateFactory.getInstance("X.509");

    // Load CA certificate from disk
    X509Certificate caCert;
    try (FileInputStream caInput = new FileInputStream(natsCaPath))
    {
      caCert = (X509Certificate) cf.generateCertificate(caInput);
    }

    // Create trust store
    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("ca", caCert);

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(trustStore);

    // Load client certificate
    Certificate clientCert;
    try (FileInputStream certInput = new FileInputStream(natsCertPath))
    {
      clientCert = cf.generateCertificate(certInput);
    }

    // Load private key
    String keyPem = new String(Files.readAllBytes(Paths.get(clientKeyPath)), StandardCharsets.UTF_8);
    java.security.PrivateKey privateKey = loadPrivateKeyFromPem(keyPem);

    // Create key store
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setKeyEntry("client", privateKey, "".toCharArray(), new Certificate[]{clientCert});

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keyStore, "".toCharArray());

    // Create SSL context
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

    return sslContext;
  }

  /**
   * Load private key from PEM using BouncyCastle
   */
  private PrivateKey loadPrivateKeyFromPem(String keyPem) throws Exception
  {
    if (keyPem == null || keyPem.trim().isEmpty())
    {
      throw new IllegalArgumentException("Empty private key PEM");
    }

    try (StringReader sr = new StringReader(keyPem);
         PEMParser pemParser = new PEMParser(sr))
    {
      Object object = pemParser.readObject();
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

      if (object == null)
      {
        throw new IllegalArgumentException("No PEM object in key material");
      }

      if (object instanceof PEMKeyPair)
      {
        PEMKeyPair keyPair = (PEMKeyPair) object;
        return converter.getPrivateKey(keyPair.getPrivateKeyInfo());
      }

      if (object instanceof PEMEncryptedKeyPair)
      {
        throw new IllegalArgumentException("Encrypted private keys not supported");
      }

      if (object instanceof PrivateKeyInfo)
      {
        return converter.getPrivateKey((PrivateKeyInfo) object);
      }

      // Fallback: try PKCS#8
      String cleaned = keyPem
        .replaceAll("-----BEGIN [^-]+-----", "")
        .replaceAll("-----END [^-]+-----", "")
        .replaceAll("\\s+", "");
      byte[] decoded = Base64.getDecoder().decode(cleaned);
      java.security.spec.PKCS8EncodedKeySpec keySpec =
        new java.security.spec.PKCS8EncodedKeySpec(decoded);

      try
      {
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
      }
      catch (Exception rsaEx)
      {
        return KeyFactory.getInstance("EC").generatePrivate(keySpec);
      }
    }
  }

  public Map<String, Object> getConnectionDebugInfo()
  {
    Map<String, Object> info = new HashMap<>();
    
    try
    {
      Connection conn = natsConnection;
      info.put("connectionExists", conn != null);
      if (conn != null)
      {
        info.put("connectionStatus", conn.getStatus().toString());
        info.put("connectionIdentity", System.identityHashCode(conn));
      }
      info.put("currentGeneration", currentGeneration.get());
      info.put("recreateInProgress", recreateInProgress.get());
      info.put("lastRecreateAttempt", lastRecreateAttemptTime.get());
      info.put("consecutiveFailures", consecutiveRecreateFailures.get());
      info.put("lastKnownCaHash", shortHash(lastKnownCaContentHash));
      info.put("appliedCaHash", shortHash(appliedCaContentHash));
      info.put("caHashMismatch", !lastKnownCaContentHash.equals(appliedCaContentHash));
    }
    catch (Exception e)
    {
      info.put("error", e.getMessage());
    }
    
    return info;
  }
  
  // ===== UTILITY METHODS =====

  /**
   * Check if exception is certificate-related
   */
  private boolean isCertificateRelatedError(Exception exp)
  {
    if (exp == null) return false;

    String msg = exp.getMessage();
    if (msg == null) return false;

    return msg.contains("certificate") ||
      msg.contains("SSL") ||
      msg.contains("TLS") ||
      msg.contains("handshake");
  }

  /**
   * Validate PEM bundle format
   */
  private boolean isValidPemBundle(String pemData)
  {
    if (pemData == null || pemData.trim().isEmpty())
    {
      return false;
    }
    return pemData.contains("-----BEGIN CERTIFICATE-----") &&
      pemData.contains("-----END CERTIFICATE-----");
  }

  /**
   * Compute SHA-256 hash of content
   */
  private String computeHash(String content) throws Exception
  {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(content.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(hash);
  }

  /**
   * Initialize CA hash at startup
   */
  private void initializeCaHash()
  {
    try
    {
      Path caPath = Paths.get(natsCaPath);
      if (Files.exists(caPath))
      {
        String content = Files.readString(caPath);
        lastKnownCaContentHash = computeHash(content);
        LOGGER.info("Initialized CA hash: {}", shortHash(lastKnownCaContentHash));
      }
    }
    catch (Exception e)
    {
      LOGGER.warn("Failed to initialize CA hash: {}", e.getMessage(), e);
    }
  }

  // ===== CERTIFICATE UPDATE CALLBACKS (for leaf cert rotation) =====

  @Override
  public void onCertificateUpdated()
  {
    if (!fullyInitialized)
    {
      LOGGER.debug("Certificate update during initialization - ignoring");
      return;
    }
   
    LOGGER.info("Leaf certificate update notification received");
    handleLeafCertificateRotation();
  }

  @Override
  public void onCertificateUpdateFailed(Exception error)
  {
    LOGGER.error("Certificate update failed", error);
    notifyCertificateUpdateFailed(error);
  }

  /**
   * Handle leaf certificate rotation (separate from CA rotation)
   * FIXED: Create new connection BEFORE closing old one
   */
  private void handleLeafCertificateRotation()
  {
    if (!fullyInitialized)
    {
      LOGGER.info("Leaf certificate update during initialization - ignored");
      return;
    }

    LOGGER.info("Handling leaf certificate rotation");

    vertx.executeBlocking(() -> {
      try
      {
        Connection oldConnection = natsConnection;
        
        LOGGER.info("╔═══════════════════════════════════════════════════════════╗");
        LOGGER.info("║ Leaf Certificate Rotation Starting                        ║");
        LOGGER.info("╚═══════════════════════════════════════════════════════════╝");

        // STEP 1: Stop timers via the consumer pool manager (single canonical place)
        if (consumerPoolManager != null)
        {
          consumerPoolManager.stopAllPullTimersSync();
        }

        // STEP 2: Create NEW connection with updated leaf cert (BEFORE closing old)
        Options.Builder builder = new Options.Builder()
          .servers(natsUrls.split(","))
          .secure()
          .sslContext(createSSLContext())  // Reads updated cert from disk
          .connectionTimeout(Duration.ofSeconds(3))
          .maxReconnects(-1)
          .connectionListener(this::handleConnectionEvent)
          .errorListener(new ErrorListener()
          {
            @Override
            public void errorOccurred(Connection conn, String error)
            {
              LOGGER.warn("NATS error: {}", error);
            }

            @Override
            public void exceptionOccurred(Connection conn, Exception exp)
            {
              if (isCertificateRelatedError(exp))
              {
                LOGGER.info("Certificate error detected: {}", exp.getMessage());
                try {
                  if (vertx != null) {
                    JsonObject evt = new JsonObject()
                      .put("serviceId", serviceId)
                      .put("error", exp.getMessage() != null ? exp.getMessage() : "certificate error")
                      .put("timestamp", System.currentTimeMillis());
                    vertx.eventBus().publish("nats.tls.exception", evt);
                  }
                } 
                catch (Throwable t) 
                {
                  LOGGER.debug("Failed to publish nats.tls.exception event: {}", t.getMessage());
                }
              }
              else
              {
                LOGGER.error("NATS exception: {}", exp == null ? "null" : exp.getMessage(), exp);
              }
            }
          });

        // Initialize expected-connection handshake BEFORE connecting
        expectedConnectionReady = new CompletableFuture<>();
        expectedConnectionRef = null;

        Connection newConn = Nats.connect(builder.build());
        
        // Mark the expected connection for the listener
        expectedConnectionRef = newConn;
        this.natsConnection = newConn;

        LOGGER.info("Created new connection identity={}", System.identityHashCode(newConn));

        // STEP 3: Wait for connection to be ready
        try
        {
          expectedConnectionReady.get(2, TimeUnit.SECONDS);
        }
        catch (TimeoutException te)
        {
          LOGGER.debug("Using polling fallback for connection ready");
          waitForConnectionReady(newConn, Duration.ofSeconds(2));
        }
        finally
        {
          // Clear handshake placeholders
          expectedConnectionRef = null;
          expectedConnectionReady = null;
        }

        // STEP 4: Verify new connection with flush
        newConn.flush(Duration.ofSeconds(1));
        LOGGER.info("✅ New connection verified");

        // STEP 5: Update generation
        long newGeneration = currentGeneration.incrementAndGet();

        // STEP 6: NOW close old connection (after new one is verified)
        if (oldConnection != null && oldConnection != newConn)
        {
          try
          {
            if (oldConnection.getStatus() == Connection.Status.CONNECTED)
            {
              oldConnection.flush(Duration.ofSeconds(1));
            }
            oldConnection.close();
            LOGGER.info("✅ Old connection closed");
          }
          catch (Exception e)
          {
            LOGGER.warn("Old connection close error: {}", e.getMessage());
          }
        }

        // STEP 7: Trigger pool recreation on event loop
        vertx.runOnContext(v -> {
          recreatePoolsWithNewConnection(newConn, newGeneration);
        });

        LOGGER.info("╔═══════════════════════════════════════════════════════════╗");
        LOGGER.info("║ ✅ Leaf Certificate Rotation Complete (Gen: {})           ║", newGeneration);
        LOGGER.info("╚═══════════════════════════════════════════════════════════╝");

        return ServiceCoreIF.SUCCESS;
      }
      catch (Exception e)
      {
        LOGGER.error("❌ Leaf cert rotation failed", e);
        throw new RuntimeException("Leaf cert rotation failed", e);
      }
    }).onComplete(ar -> {
      if (ar.failed())
      {
        notifyCertificateUpdateFailed(new Exception(ar.cause()));
      }
      else
      {
        // DO NOT call notifyCallbacks() here - already done in recreatePoolsWithNewConnection
        LOGGER.debug("Leaf certificate rotation completed successfully");
      }
    });
  }
  
  /**
   * Handle leaf certificate rotation (separate from CA rotation)
  private void handleLeafCertificateRotation()
  {
    if (!fullyInitialized)
    {
      LOGGER.info("Leaf certificate update during initialization - ignored");
      return;
    }

    LOGGER.info("Handling leaf certificate rotation");

    vertx.executeBlocking(() -> {
      try
      {
        Connection oldConnection = natsConnection;

        // Close old connection
        if (oldConnection != null)
        {
          oldConnection.close();
        }

        Thread.sleep(1000);

        // Create new connection with new leaf cert
        buildTlsConnectionWithListeners();

        // Recreate pools
        long newGeneration = currentGeneration.incrementAndGet();
        recreatePoolsWithNewConnection(natsConnection, newGeneration);

        LOGGER.info("Leaf certificate rotation completed");
        return ServiceCoreIF.SUCCESS;
      }
      catch (Exception e)
      {
        throw new RuntimeException("Leaf cert rotation failed", e);
      }
    }).onComplete(ar -> {
      if (ar.failed())
      {
        notifyCertificateUpdateFailed(new Exception(ar.cause()));
      }
      else
      {
        notifyCallbacks();
      }
    });
  }
   */

  // ===== PUBLIC API METHODS =====
 
  /**
   * Handle CA bundle update - Proactive connection recreation
   */
  public Future<Void> handleCaBundleUpdate( CaBundle caBundle )
  {
    if (!fullyInitialized)
    {
      LOGGER.warn("CA bundle update during initialization - deferring");
      
      Promise<Void> deferred = Promise.promise();
      vertx.setTimer(1000, id -> {
        if (fullyInitialized)
        {
          handleCaBundleUpdate(caBundle).onComplete(deferred);
        }
        else
        {
          deferred.fail("Not initialized");
        }
      });
      return deferred.future();
    }

    LOGGER.info( "📦 CA Bundle update - Server: {}, Epoch: {}", caBundle.getServerId(), caBundle.getCaEpochNumber() );

    return workerExecutor.executeBlocking( () -> {
      String caBundleStr = caBundle.getCaBundle();

      // Validate PEM format
      if( !isValidPemBundle( caBundleStr ) )
      {
        throw new RuntimeException( "Invalid PEM format in CA bundle" );
      }

      // Compute hash and check for changes
      String newHash = computeHash( caBundleStr );
      boolean caChanged = !newHash.equals( lastKnownCaContentHash );

      if( !caChanged )
      {
        LOGGER.info( "CA bundle unchanged (hash: {}) - skipping rotation", shortHash( newHash ) );
        return null; // Return null to signal no change
      }

      LOGGER.info( "New CA hash: {} (old: {})", shortHash( newHash ), lastKnownCaContentHash.isEmpty() ? "none" : shortHash( lastKnownCaContentHash ) );

      // Write new CA file atomically
      Path caFilePath = Paths.get( natsCaPath );
      Files.createDirectories( caFilePath.getParent() );
      Path tempFile = Paths.get( natsCaPath + ".tmp" );
      Files.write( tempFile, caBundleStr.getBytes( StandardCharsets.UTF_8 ) );

      try
      {
        Files.move( tempFile, caFilePath, java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING );
      }
      catch( Exception moveEx )
      {
        LOGGER.debug( "Atomic move failed, using regular move: {}", moveEx.getMessage() );
        Files.move( tempFile, caFilePath, java.nio.file.StandardCopyOption.REPLACE_EXISTING );
      }

      if( !Files.exists( caFilePath ) || !Files.isReadable( caFilePath ) )
      {
        throw new IOException( "CA file not created successfully at: " + caFilePath );
      }

      // Verify file hash matches expected
      String writtenContent = Files.readString( caFilePath );
      String writtenHash = computeHash( writtenContent );

      if( !writtenHash.equals( newHash ) )
      {
        throw new IOException( String.format( "CA file hash mismatch after write! Expected: %s, Got: %s", shortHash( newHash ), shortHash( writtenHash ) ) );
      }

      // Update hash tracking - Mark pending so DISCONNECTED handler will apply
      // if needed
      lastKnownCaContentHash = newHash;

      LOGGER.info( "✅ CA file written and verified - hash: {}", shortHash( newHash ) );
      return newHash;
    } ).compose( hash -> {
      if( hash == null )
        return Future.succeededFuture();

      if( !recreateInProgress.compareAndSet( false, true ) )
      {
        LOGGER.info( "Recreate already in progress; skipping proactive recreate" );
        return Future.succeededFuture();
      }

      // Run the recreate flow asynchronously
      return reconnectWithRetry( 0 ).onComplete( ar -> {
        recreateInProgress.set( false );
        if( ar.succeeded() )
        {
          // appliedCaContentHash is already set inside
          // recreateConnectionWithNewCA
          // DO NOT call notifyCallbacks() here - the pool managers were already
          // notified directly during recreatePoolsWithNewConnection().
          // Calling notifyCallbacks() again would trigger
          // onCertificateUpdated()
          // a SECOND time, causing double-migration!
          LOGGER.debug( "CA rotation reconnect completed successfully" );
        }
        else
        {
          notifyCertificateUpdateFailed( new Exception( ar.cause() ) );
        }
      } );
    } );
  }
  
  public Future<Void> publish(String subject, byte[] data)
  {
    return producerPoolManager.sendMessage(subject, data, null);
  }

  public Future<Void> publish(String subject, byte[] data, Map<String, String> headers)
  {
    return producerPoolManager.sendMessage(subject, data, headers);
  }

  /**
   * Expose the applied CA hash so external components can compare state.
   */
  public String getAppliedCaContentHash()
  {
    return appliedCaContentHash;
  }
  
/**  
  public Future<Subscription> subscribe(String subject, MessageHandler handler)
  {
    return consumerPoolManager.getOrCreateConsumer(subject, serviceId + "-subscription", handler);
  }
*/
  public Connection getConnectionForNewOperations()
  {
    return natsConnection;
  }

  public long getCurrentGeneration()
  {
    return currentGeneration.get();
  }

  public NatsProducerPoolManager getProducerPoolManager()
  {
    return producerPoolManager;
  }

  public NatsConsumerPoolManager getConsumerPoolManager()
  {
    return consumerPoolManager;
  }

  public Map<String, ConsumerDescriptor> getRegisteredConsumers()
  {
    return consumerPoolManager.getRegisteredConsumers();
  }

  public Connection getNatsConnection()
  {
    return natsConnection;
  }

  public String getNatsCaPath()
  {
    return natsCaPath;
  }

  public boolean isHealthy()
  {
    try
    {
      return natsConnection != null &&
        natsConnection.getStatus() == Connection.Status.CONNECTED;
    }
    catch (Exception e)
    {
      return false;
    }
  }

  // ===== CALLBACK MANAGEMENT =====

  public void addCertificateUpdateCallback(CertificateUpdateCallbackIF callback)
  {
    if (callback != null && !additionalCallbacks.contains(callback))
    {
      additionalCallbacks.add(callback);
      LOGGER.debug("Added certificate update callback: {}", callback.getClass().getSimpleName());
    }
  }

  private void notifyCallbacks()
  {
    for (CertificateUpdateCallbackIF callback : additionalCallbacks)
    {
      try
      {
        callback.onCertificateUpdated();
      }
      catch (Exception e)
      {
        LOGGER.error("Error notifying callback: {}", callback.getClass().getSimpleName(), e);
      }
    }
  }

  private void notifyCertificateUpdateFailed(Exception e)
  {
    for (CertificateUpdateCallbackIF callback : additionalCallbacks)
    {
      try
      {
        callback.onCertificateUpdateFailed(e);
      }
      catch (Exception ex)
      {
        LOGGER.error("Error notifying callback of failure: {}",
          callback.getClass().getSimpleName(), ex);
      }
    }
  }

  // ===== INITIALIZATION & VALIDATION =====

  private void initializeWritableCaFile() throws IOException
  {
    final int maxRetries = 5;
    final long retryDelayMs = 2000;

    LOGGER.info("Initializing writable CA file at: {}", natsCaPath);

    for (int attempt = 1; attempt <= maxRetries; attempt++)
    {
      try
      {
        Secret caSecret = kubeClient.secrets()
          .inNamespace(namespace)
          .withName("nats-ca-secret")
          .get();

        if (caSecret == null || caSecret.getData() == null)
        {
          throw new IOException("CA secret not found: nats-ca-secret");
        }

        String caCertB64 = caSecret.getData().get("ca.crt");
        if (caCertB64 == null || caCertB64.trim().isEmpty())
        {
          throw new IOException("CA certificate data not found in secret");
        }

        byte[] caCertBytes = Base64.getDecoder().decode(caCertB64);
        Path caFilePath = Paths.get(natsCaPath);

        Files.createDirectories(caFilePath.getParent());
        Files.write(caFilePath, caCertBytes);

        if (!Files.exists(caFilePath) || !Files.isReadable(caFilePath))
        {
          throw new IOException("CA file not created successfully");
        }

        LOGGER.info("Successfully initialized writable CA file: {} ({} bytes)",
          caFilePath, Files.size(caFilePath));
        return;
      }
      catch (Exception e)
      {
        LOGGER.warn("Attempt {}/{} failed to initialize CA file: {}",
          attempt, maxRetries, e.getMessage());
        if (attempt < maxRetries)
        {
          try
          {
            Thread.sleep(retryDelayMs);
          }
          catch (InterruptedException ie)
          {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted during CA file init retry", ie);
          }
        }
        else
        {
          throw new IOException("Failed to initialize CA file after " + maxRetries + " attempts", e);
        }
      }
    }
  }

  private void validateConfiguration()
  {
    if (clientSecretName == null || clientSecretName.isEmpty())
    {
      throw new IllegalArgumentException("NATS Client Secret not set");
    }
    if (natsUrls == null || natsUrls.isEmpty())
    {
      throw new IllegalArgumentException("NATS URL not set");
    }
    if (natsCaPath == null || natsCaPath.isEmpty())
    {
      throw new IllegalArgumentException("NATS TLS CA path not set");
    }
    if (natsCertPath == null || natsCertPath.isEmpty())
    {
      throw new IllegalArgumentException("NATS TLS certificate path not set");
    }
  }

  private void validateCertificateFiles() throws Exception
  {
    File caCertFile = new File(natsCaPath);
    File clientCertFile = new File(natsCertPath);
    File clientKeyFile = new File(clientKeyPath);

    if (!caCertFile.exists() || !caCertFile.canRead())
    {
      throw new Exception("CA certificate file not found: " + natsCaPath);
    }
    if (!clientCertFile.exists() || !clientCertFile.canRead())
    {
      throw new Exception("Client certificate file not found: " + natsCertPath);
    }
    if (!clientKeyFile.exists() || !clientKeyFile.canRead())
    {
      throw new Exception("Client key file not found: " + clientKeyPath);
    }

    LOGGER.info("All certificate files validated successfully");
  }

  private void waitForNatsReady() throws Exception
  {
    final int maxAttempts = 10;
    final long delayMs = 3000;

    LOGGER.info("Waiting for NATS server to be ready at {}", natsUrls);

    for (int attempt = 1; attempt <= maxAttempts; attempt++)
    {
      Connection testConnection = null;
      try
      {
        Options.Builder builder = new Options.Builder()
          .servers(natsUrls.split(","))
          .secure()
          .sslContext(createSSLContext())
          .connectionTimeout(Duration.ofSeconds(10));

        testConnection = Nats.connect(builder.build());
        testConnection.publish("test.subject", "hello".getBytes());
        testConnection.flush(Duration.ofSeconds(5));

        LOGGER.info("NATS validated successfully (attempt {})", attempt);
        return;
      }
      catch (Exception e)
      {
        LOGGER.warn("Attempt {}: NATS connection test failed: {}", attempt, e.getMessage(), e);
      }
      finally
      {
        if (testConnection != null)
        {
          try
          {
            testConnection.close();
          }
          catch (Exception e)
          {
            LOGGER.debug("Error closing test connection: {}", e.getMessage());
          }
        }
      }

      if (attempt < maxAttempts)
      {
        Thread.sleep(delayMs);
      }
    }

    throw new Exception("NATS not ready after " + maxAttempts + " attempts");
  }

  // ===== CLEANUP =====

  public void cleanup()
  {
    try
    {
      if (producerPoolManager != null)
      {
        producerPoolManager.shutdown();
      }
      if (consumerPoolManager != null)
      {
        consumerPoolManager.shutdown();
      }
      if (natsConnection != null)
      {
        natsConnection.close();
      }
      if (certificateManager != null)
      {
        certificateManager.close();
      }
      if (caSecretManager != null)
      {
        caSecretManager.close();
      }
      if (workerExecutor != null)
      {
        workerExecutor.close();
      }
    }
    catch (Exception e)
    {
      LOGGER.error("Error during cleanup: {}", e.getMessage(), e);
    }

    LOGGER.info("NatsTLSClient cleanup successful");
  }
}