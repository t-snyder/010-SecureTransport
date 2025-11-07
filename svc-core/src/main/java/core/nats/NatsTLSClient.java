package core.nats;

import core.handler.CaSecretManager;
import core.handler.CertificateManager;
import core.handler.CertificateUpdateCallbackIF;
import core.model.CaBundle;
import core.model.ServiceCoreIF;
import core.nats.NatsProducerPoolManager;
import core.nats.NatsConsumerPoolManager;
import core.utils.CaRotationWindowManager;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.nats.client.*;
import io.nats.client.api.ConsumerInfo;
import io.nats.client.api.StreamInfo;
import io.nats.client.impl.NatsMessage;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class NatsTLSClient implements CertificateUpdateCallbackIF
{
  private static final Logger LOGGER = LoggerFactory.getLogger(NatsTLSClient.class);

  private final List<CertificateUpdateCallbackIF> additionalCallbacks = new ArrayList<>();

  public static final String NATS_URLS = "NatsUrls";
  public static final String NATS_CA_CERT_PATH = "NatsCACertPath";
  public static final String NATS_CLIENT_CERT_PATH = "NatsClientCertPath";
  public static final String NATS_CLIENT_SECRET = "NatsClientSecret";

  // Config Parameters
  private String serviceId;
  private String natsUrls;
  private String natsCaPath;
  private String natsCertPath;
  private String clientSecretName;
  private String clientKeyPath;

  // Runtime vars
  private Vertx vertx;
  private Connection natsConnection;
  private CertificateManager certificateManager;
  private CaSecretManager caSecretManager;
  private WorkerExecutor workerExecutor;

  // Enhanced connection state tracking
  private final AtomicBoolean isReconnecting = new AtomicBoolean(false);
  private final AtomicBoolean migrationInProgress = new AtomicBoolean(false);
  private final AtomicLong currentGeneration = new AtomicLong(1);
  private final AtomicLong migrationGeneration = new AtomicLong(0);

  // Migration support
  private volatile Connection newConnectionDuringMigration = null;

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
      String msg = "Config can not be null or empty.";
      LOGGER.error(msg);
      throw new IllegalArgumentException(msg);
    }

    this.vertx = vertx;
    this.kubeClient = kubeClient;
    this.namespace = namespace;
    this.serviceId = serviceId;

    this.natsUrls = config.get(NATS_URLS);
    this.natsCaPath = config.get(NATS_CA_CERT_PATH);
    this.natsCertPath = config.get(NATS_CLIENT_CERT_PATH);
    this.clientSecretName = config.get(NATS_CLIENT_SECRET);

    LOGGER.info("*** NATS url = " + natsUrls + "; caCertPath = " + natsCaPath + 
                "; natsCertPath = " + natsCertPath + "; secret name = " + clientSecretName);

    workerExecutor = vertx.createSharedWorkerExecutor("nats-client-worker", 2, 360000, TimeUnit.MILLISECONDS);
    this.caSecretManager = new CaSecretManager(kubeClient, namespace, serviceId);

    // Initialize CA file BEFORE certificate manager
    try
    {
      initializeWritableCaFile();
    } 
    catch (IOException e)
    {
      LOGGER.error("Failed to initialize writable CA file", e);
      throw new Exception(e);
    }

    this.certificateManager = new CertificateManager(kubeClient, namespace, clientSecretName, 
                                                     natsCaPath, natsCertPath, this);

    // Wait for certificates to be ready
    try
    {
      certificateManager.initialize().get();
      this.natsCertPath = certificateManager.getCertPath();
      this.clientKeyPath = certificateManager.getKeyPath();
      LOGGER.info("Certificate paths initialized - Cert: {}, Key: {}", natsCertPath, clientKeyPath);
    } 
    catch (Exception e)
    {
      LOGGER.error("Failed to initialize certificates", e);
      throw new Exception(e);
    }

    validateConfiguration();
    validateCertificateFiles();

    try
    {
      waitForNatsReady();
    } 
    catch (Exception e)
    {
      String errMsg = "Failed to validate NATS is Up and Ready. Error = " + e.getMessage();
      LOGGER.error(errMsg);
      throw new Exception(errMsg);
    }

    buildTlsConnection();

    this.producerPoolManager = new NatsProducerPoolManager(vertx, this);
    this.consumerPoolManager = new NatsConsumerPoolManager(vertx, this);

    this.addCertificateUpdateCallback(producerPoolManager);
    this.addCertificateUpdateCallback(consumerPoolManager);

    LOGGER.info("NATS client is initialized.");
  }

  /**
   * Handle CA bundle update with graceful rotation
   */
  public Future<Void> handleCaBundleUpdate(String caBundleStr)
  {
    try
    {
      String serverId = (this.serviceId != null && !this.serviceId.isBlank()) ? this.serviceId : "NATS";
      String caVersion = Instant.now().toString();
      long caEpoch = currentGeneration.get();
      CaBundle cb = new CaBundle(serverId, Instant.now(), caEpoch, 
                                ServiceCoreIF.CaRotationEvent, caBundleStr, caVersion);
      
      return handleCaBundleUpdate(cb);
    } 
    catch (Exception e)
    {
      LOGGER.error("Failed to handle CA bundle update from String overload", e);
      notifyCertificateUpdateFailed(new Exception(e));
      return Future.failedFuture(e);
    }
  }

  public Future<Void> handleCaBundleUpdate(CaBundle caBundle)
  {
    Promise<Void> outer = Promise.promise();

    LOGGER.info("Received CA bundle update - Server: {}, Version: {}, Epoch: {}", 
                caBundle.getServerId(), caBundle.getCaVersion(), caBundle.getCaEpochNumber());

    workerExecutor.executeBlocking(() -> 
    {
      // Validate PEM format
      String caBundleStr = caBundle.getCaBundle();
      if (!isValidPemBundle(caBundleStr))
      {
        throw new RuntimeException("Invalid PEM format in CA bundle");
      }

      // Update Kubernetes secret
      caSecretManager.updateCaSecret(caBundle);

      // Write atomically to writable CA file
      try
      {
        Path caFilePath = Paths.get(natsCaPath);
        Files.createDirectories(caFilePath.getParent());
        Path tempFile = Paths.get(natsCaPath + ".tmp");
        Files.write(tempFile, caBundleStr.getBytes(StandardCharsets.UTF_8));

        try
        {
          Files.move(tempFile, caFilePath, 
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE, 
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } 
        catch (Exception moveEx)
        {
          Files.move(tempFile, caFilePath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }

        if (!Files.exists(caFilePath) || !Files.isReadable(caFilePath))
        {
          throw new IOException("CA file was not created successfully or is not readable");
        }

        LOGGER.info("Atomically updated writable CA file: {}", caFilePath);
      } 
      catch (Exception e)
      {
        throw new RuntimeException("Failed writing CA file atomically: " + e.getMessage(), e);
      }

      return null;
    }).onComplete(ar -> {
      if (ar.failed())
      {
        LOGGER.error("Failed to stage CA bundle update", ar.cause());
        notifyCertificateUpdateFailed(new Exception(ar.cause()));
        outer.fail(ar.cause());
        return;
      }

      initiateGracefulCaRotation().onSuccess(v -> {
        LOGGER.info("CA bundle rotation completed successfully");
        outer.complete();
      }).onFailure(err -> {
        LOGGER.error("CA bundle rotation failed", err);
        notifyCertificateUpdateFailed(new Exception(err));
        outer.fail(err);
      });
    });

    return outer.future();
  }

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
   * Build TLS connection to NATS
   */
  private void buildTlsConnection() throws Exception
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
          .sslContext(createSSLContext())
          .reconnectWait(Duration.ofSeconds(2))
          .maxReconnects(10)
          .connectionTimeout(Duration.ofSeconds(15));

        natsConnection = Nats.connect(builder.build());
        LOGGER.info("NATS connection established with TLS");
        break;
      } 
      catch (Exception e)
      {
        CaRotationWindowManager.logConnectionError(LOGGER, 
          "Error building NATS connection (attempt " + attempt + "/" + maxRetries + ")", e);
        
        if (attempt == maxRetries)
        {
          String msg = "Failed to build NATS connection after " + maxRetries + " attempts: " + e.getMessage();
          LOGGER.error(msg, e);
          throw new Exception(msg, e);
        }

        try
        {
          Thread.sleep(retryDelay);
        } 
        catch (InterruptedException ie)
        {
          Thread.currentThread().interrupt();
          throw new Exception("Interrupted during retry delay", ie);
        }
      }
    }
  }

  /**
   * Create SSL context for NATS TLS connection
   */
  private SSLContext createSSLContext() throws Exception
  {
    // Load CA certificate
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    FileInputStream caInput = new FileInputStream(natsCaPath);
    X509Certificate caCert = (X509Certificate) cf.generateCertificate(caInput);
    caInput.close();

    // Create trust store
    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("ca", caCert);

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(trustStore);

    // Load client certificate and key
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);

    // Load client certificate
    FileInputStream certInput = new FileInputStream(natsCertPath);
    Certificate clientCert = cf.generateCertificate(certInput);
    certInput.close();

    // Load private key (assuming PKCS#8 format)
    byte[] keyBytes = Files.readAllBytes(Paths.get(clientKeyPath));
    String keyContent = new String(keyBytes, StandardCharsets.UTF_8)
      .replace("-----BEGIN PRIVATE KEY-----", "")
      .replace("-----END PRIVATE KEY-----", "")
      .replaceAll("\\s", "");
    
    byte[] decodedKey = Base64.getDecoder().decode(keyContent);
    java.security.spec.PKCS8EncodedKeySpec keySpec = 
      new java.security.spec.PKCS8EncodedKeySpec(decodedKey);
    java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
    java.security.PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

    keyStore.setKeyEntry("client", privateKey, "".toCharArray(), new Certificate[]{clientCert});

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keyStore, "".toCharArray());

    // Create SSL context
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

    return sslContext;
  }

  /**
   * Publish message to NATS subject
   */
  public Future<Void> publish(String subject, byte[] data)
  {
    return producerPoolManager.sendMessage(subject, data, null);
  }

  public Future<Void> publish(String subject, byte[] data, java.util.Map<String, String> headers)
  {
    return producerPoolManager.sendMessage(subject, data, headers);
  }

  /**
   * Subscribe to NATS subject
   */
  public Future<Subscription> subscribe(String subject, MessageHandler handler)
  {
    return consumerPoolManager.getOrCreateConsumer(subject, serviceId + "-subscription", handler);
  }

  /**
   * Get connection for new operations during migration
   */
  public Connection getConnectionForNewOperations()
  {
    return migrationInProgress.get() && newConnectionDuringMigration != null ? 
           newConnectionDuringMigration : natsConnection;
  }

  public long getCurrentGeneration()
  {
    return migrationInProgress.get() ? migrationGeneration.get() : currentGeneration.get();
  }

  public boolean isMigrationInProgress()
  {
    return migrationInProgress.get();
  }

  public NatsProducerPoolManager getProducerPoolManager()
  {
    return producerPoolManager;
  }

  public NatsConsumerPoolManager getConsumerPoolManager()
  {
    return consumerPoolManager;
  }

  // Certificate update callback implementation
  @Override
  public void onCertificateUpdated()
  {
    LOGGER.info("Leaf certificate update notification received");
    if (migrationInProgress.get())
    {
      LOGGER.info("Ignoring leaf certificate update during CA rotation");
      return;
    }
    handleLeafCertificateRotation();
  }

  @Override
  public void onCertificateUpdateFailed(Exception error)
  {
    LOGGER.error("Certificate update failed, NATS client may become unavailable", error);
    notifyCertificateUpdateFailed(error);
  }

  private void handleLeafCertificateRotation()
  {
    if (isReconnecting.getAndSet(true))
    {
      LOGGER.warn("Leaf certificate rotation already in progress");
      return;
    }

    LOGGER.info("Handling leaf certificate rotation");
    
    workerExecutor.executeBlocking(() -> {
      try
      {
        if (natsConnection != null)
        {
          LOGGER.info("Closing existing NATS connection for leaf certificate rotation");
          natsConnection.close();
        }

        Thread.sleep(1000);
        LOGGER.info("Rebuilding NATS connection with updated leaf certificates");
        buildTlsConnection();
        LOGGER.info("Leaf certificate rotation completed successfully");
        return ServiceCoreIF.SUCCESS;
      } 
      catch (Exception e)
      {
        String errMsg = "Failed to rotate leaf certificates. Error = " + e.getMessage();
        LOGGER.error(errMsg);
        throw new RuntimeException(errMsg, e);
      } 
      finally
      {
        isReconnecting.set(false);
      }
    }).onComplete(ar -> {
      if (ar.failed())
      {
        LOGGER.error("Leaf certificate rotation failed", ar.cause());
        notifyCertificateUpdateFailed(new Exception(ar.cause()));
      } 
      else
      {
        LOGGER.info("Leaf certificate rotation completed successfully");
        notifyCallbacks();
      }
    });
  }

  private Future<Void> initiateGracefulCaRotation()
  {
    Promise<Void> promise = Promise.promise();

    if (!isReconnecting.compareAndSet(false, true))
    {
      LOGGER.warn("CA rotation already in progress");
      promise.fail("in-progress");
      return promise.future();
    }

    LOGGER.info("Initiating graceful CA rotation");

    vertx.setTimer(1000, delayId -> {
      try
      {
        Connection newConnection = createNewConnectionWithUpdatedCa();
        long newGeneration = currentGeneration.incrementAndGet();
        
        migrationInProgress.set(true);
        migrationGeneration.set(newGeneration);
        newConnectionDuringMigration = newConnection;

        startGracefulMigrationInPools(newConnection, newGeneration);
        
        // Wait for migration to complete
        vertx.setTimer(30000, completionId -> {
          completeMigration(newConnection);
          isReconnecting.set(false);
          promise.complete();
        });
      } 
      catch (Exception e)
      {
        isReconnecting.set(false);
        promise.fail(e);
      }
    });

    return promise.future();
  }

  private Connection createNewConnectionWithUpdatedCa() throws Exception
  {
    LOGGER.info("Creating new NATS connection with updated CA bundle");
    
    Options.Builder builder = new Options.Builder()
      .servers(natsUrls.split(","))
      .secure()
      .sslContext(createSSLContext())
      .reconnectWait(Duration.ofSeconds(2))
      .maxReconnects(10)
      .connectionTimeout(Duration.ofSeconds(15));

    return Nats.connect(builder.build());
  }

  private void startGracefulMigrationInPools(Connection newConnection, long newGeneration)
  {
    LOGGER.info("Starting graceful migration in producer and consumer pools");
    
    for (CertificateUpdateCallbackIF callback : additionalCallbacks)
    {
      try
      {
        if (callback instanceof GracefulMigrationCapable)
        {
          ((GracefulMigrationCapable) callback).startGracefulMigration(newConnection, newGeneration);
        }
      } 
      catch (Exception e)
      {
        LOGGER.error("Error starting graceful migration for callback: {}", 
                     callback.getClass().getSimpleName(), e);
      }
    }
  }

  private void completeMigration(Connection newConnection)
  {
    LOGGER.info("Completing graceful migration");
    
    try
    {
      if (natsConnection != null)
      {
        LOGGER.info("Closing old NATS connection");
        natsConnection.close();
      }

      this.natsConnection = newConnection;
      this.newConnectionDuringMigration = null;

      for (CertificateUpdateCallbackIF callback : additionalCallbacks)
      {
        try
        {
          if (callback instanceof GracefulMigrationCapable)
          {
            ((GracefulMigrationCapable) callback).completeMigration();
          } 
          else
          {
            callback.onCertificateUpdated();
          }
        } 
        catch (Exception e)
        {
          LOGGER.error("Error completing migration for callback: {}", 
                       callback.getClass().getSimpleName(), e);
        }
      }

      migrationInProgress.set(false);
      LOGGER.info("CA rotation migration completed successfully");
    } 
    catch (Exception e)
    {
      LOGGER.error("Error during migration completion", e);
      rollbackMigration();
    }
  }

  private void rollbackMigration()
  {
    LOGGER.warn("Rolling back CA rotation migration");
    
    try
    {
      if (newConnectionDuringMigration != null)
      {
        newConnectionDuringMigration.close();
        newConnectionDuringMigration = null;
      }

      migrationInProgress.set(false);

      for (CertificateUpdateCallbackIF callback : additionalCallbacks)
      {
        try
        {
          if (callback instanceof GracefulMigrationCapable)
          {
            ((GracefulMigrationCapable) callback).rollbackMigration();
          }
        } 
        catch (Exception e)
        {
          LOGGER.warn("Error during rollback for callback: {}", 
                      callback.getClass().getSimpleName(), e);
        }
      }
    } 
    catch (Exception e)
    {
      LOGGER.error("Error during migration rollback", e);
    }
  }

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
    LOGGER.info("Notifying {} callbacks of certificate update", additionalCallbacks.size());
    
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
        LOGGER.error("Error notifying callback of certificate update failure: {}", 
                     callback.getClass().getSimpleName(), ex);
      }
    }
  }

  private void initializeWritableCaFile() throws IOException
  {
    // Implementation similar to PulsarTLSClient but for NATS CA file
    final int maxRetries = 5;
    final long retryDelayMs = 2000;

    LOGGER.info("Initializing writable CA file at: {}", natsCaPath);

    Exception lastException = null;

    for (int attempt = 1; attempt <= maxRetries; attempt++)
    {
      try
      {
        Secret caSecret = kubeClient.secrets().inNamespace(namespace).withName("nats-ca-secret").get();
        
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

        Path tempFile = Paths.get(natsCaPath + ".tmp");
        Files.write(tempFile, caCertBytes);
        Files.move(tempFile, caFilePath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        if (!Files.exists(caFilePath) || !Files.isReadable(caFilePath))
        {
          throw new IOException("CA file was not created successfully or is not readable");
        }

        byte[] writtenContent = Files.readAllBytes(caFilePath);
        if (writtenContent.length == 0)
        {
          throw new IOException("CA file was created but is empty");
        }

        LOGGER.info("Successfully initialized writable CA file: {} (size: {} bytes)", 
                   caFilePath, writtenContent.length);
        return;
      } 
      catch (Exception e)
      {
        lastException = e;
        LOGGER.warn("Attempt {}/{} failed to initialize CA file: {}", attempt, maxRetries, e.getMessage());

        if (attempt < maxRetries)
        {
          try
          {
            Thread.sleep(retryDelayMs);
          } 
          catch (InterruptedException ie)
          {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted during CA file initialization retry", ie);
          }
        }
      }
    }

    String msg = String.format("Failed to initialize CA file after %d attempts", maxRetries);
    LOGGER.error(msg, lastException);
    throw new IOException(msg, lastException);
  }

  private void validateConfiguration()
  {
    if (clientSecretName == null || clientSecretName.length() == 0)
    {
      String msg = "NATS Client Secret is not set.";
      LOGGER.error(msg);
      throw new IllegalArgumentException(msg);
    }

    if (natsUrls == null || natsUrls.length() == 0)
    {
      String msg = "NATS URL is not set.";
      LOGGER.error(msg);
      throw new IllegalArgumentException(msg);
    }

    if (natsCaPath == null || natsCaPath.length() == 0)
    {
      String msg = "NATS TLS CA path is not set.";
      LOGGER.error(msg);
      throw new IllegalArgumentException(msg);
    }

    if (natsCertPath == null || natsCertPath.length() == 0)
    {
      String msg = "NATS TLS certificate path is not set.";
      LOGGER.error(msg);
      throw new IllegalArgumentException(msg);
    }
  }

  private void validateCertificateFiles() throws Exception
  {
    try
    {
      File caCertFile = new File(natsCaPath);
      File clientCertFile = new File(natsCertPath);
      File clientKeyFile = new File(clientKeyPath);

      if (!caCertFile.exists() || !caCertFile.canRead())
      {
        throw new Exception("CA certificate file not found or not readable: " + natsCaPath);
      }

      if (!clientCertFile.exists() || !clientCertFile.canRead())
      {
        throw new Exception("Client certificate file not found or not readable: " + natsCertPath);
      }

      if (!clientKeyFile.exists() || !clientKeyFile.canRead())
      {
        throw new Exception("Client key file not found or not readable: " + clientKeyPath);
      }

      LOGGER.info("All certificate files validated successfully");
    } 
    catch (Exception e)
    {
      String msg = "Certificate file validation failed: " + e.getMessage();
      LOGGER.error(msg, e);
      throw new Exception(msg, e);
    }
  }

  private void waitForNatsReady() throws Exception
  {
    final int maxAttempts = 10;
    final long delayMs = 3000;
    final long maxDelay = 60000;

    LOGGER.info("Waiting for NATS server to be ready at {}", natsUrls);

    Exception lastException = null;

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
        
        // Test the connection
        testConnection.publish("test.subject", "hello".getBytes());
        testConnection.flush(Duration.ofSeconds(5));

        LOGGER.info("NATS connection validated successfully (attempt {})", attempt);
        return;
      } 
      catch (Exception e)
      {
        lastException = e;
        CaRotationWindowManager.logConnectionError(LOGGER, 
          "Attempt " + attempt + ": NATS connection test failed", e);
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
        long doDelay = Math.min(delayMs * attempt, maxDelay);
        LOGGER.info("Waiting {} ms before retry (attempt {}/{})", doDelay, attempt, maxAttempts);
        try
        {
          Thread.sleep(doDelay);
        } 
        catch (InterruptedException ie)
        {
          Thread.currentThread().interrupt();
          throw new Exception("Interrupted while waiting for NATS", ie);
        }
      }
    }

    String msg = String.format("NATS not ready after %d attempts. Last error: %s", 
                               maxAttempts, lastException != null ? lastException.getMessage() : "Unknown");
    LOGGER.error(msg, lastException);
    throw new Exception(msg, lastException);
  }

  public boolean isHealthy()
  {
    try
    {
      return natsConnection != null && natsConnection.getStatus() == Connection.Status.CONNECTED 
             && !isReconnecting.get();
    } 
    catch (Exception e)
    {
      return false;
    }
  }

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
      if (newConnectionDuringMigration != null)
      {
        newConnectionDuringMigration.close();
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
      LOGGER.error("Error during cleanup: {}", e.getMessage());
    }

    LOGGER.info("NatsTLSClient cleanup successful.");
  }

  public Connection getNatsConnection()
  {
    return natsConnection;
  }

  // Inner interface for graceful migration support
  public interface GracefulMigrationCapable
  {
    void startGracefulMigration(Connection newConnection, long newGeneration);
    void completeMigration();
    void rollbackMigration();
    int getActiveOldGenerationConnections();
  }
}