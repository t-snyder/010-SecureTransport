package verticle;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;

//import io.nats.client.Message;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.crypto.EncryptedData;
import core.crypto.AesGcmHkdfCrypto;
import core.handler.KeySecretManager;
import core.model.CaBundle;
import core.model.DilithiumKey;
import core.model.ServiceCoreIF;
import core.model.service.TopicKey;
import core.nats.NatsTLSClient;
import core.service.DilithiumService;
import core.transport.SignedMessage;
import core.utils.CaRotationWindowManager;
import core.utils.KeyEpochUtil;

import handler.MetadataVaultHandler;
import helper.MetadataConfig;
import utils.CAEpochUtil;
import utils.RotationConfig;

import java.nio.charset.StandardCharsets;
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CaRotatorVert - Enhanced CA bundle rotation with NATS JetStream support
 */
public class CaRotatorVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger( CaRotatorVert.class );

  private static final String VAULT_ROOT_CA_PATH = "pki";
  private static final String NATS_PKI_MOUNT = "nats_int";  // Changed from pulsar_int

  private static final String CERT_TYPE = "rsa";
  private static final int    CERT_STRENGTH = 4096;

  // Local metadata service secret (this service's namespace)
  private static final String LOCAL_CA_SECRET_NAME = "nats-ca-secret";  // Changed from pulsar-ca-secret
  private static final String LOCAL_CA_SECRET_KEY = "ca.crt";

  // PEM certificate validation patterns
  private static final Pattern PEM_CERT_PATTERN = Pattern.compile(
    "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----"
  );
  private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/]*={0,2}$");

  private KubernetesClient       kubeClient;
  private NatsTLSClient          natsTLSClient;  // Changed from PulsarTLSClient
  private WorkerExecutor         workerExecutor;
  private MetadataVaultHandler   metadataVaultHandler;

  private final MetadataConfig   config;
  private final DilithiumService signer;
  private final KeySecretManager keyCache;
  private final AesGcmHkdfCrypto aesCrypto = new AesGcmHkdfCrypto();
  private final RotationConfig   rotationConfig;
  private final CAEpochUtil      caEpoch;

  private String namespace;
  private long   timerId = -1;

  // startup timer id (one-shot) used to delay initial rotation
  private long    startupTimerId = -1;
  private Instant startupInstant;

  // Minimum delay before the first rotation check (default 3 minutes).
  private static final Duration INITIAL_ROTATION_DELAY = Duration.ofMinutes(3);

  // Track last epoch that we've performed a rotation for so we don't run twice for the same epoch.
  private volatile long lastRotatedEpoch = Long.MIN_VALUE;

  // Enhanced retry configuration
  private static final int MAX_ROTATION_RETRIES = 3;
  private static final Duration ROTATION_RETRY_DELAY = Duration.ofSeconds(30);

  public CaRotatorVert( Vertx vertx, KubernetesClient kubeClient, NatsTLSClient natsTLSClient,
                       MetadataVaultHandler metadataVaultHandler, MetadataConfig config,
                       DilithiumService signer, KeySecretManager keyCache )
  {
    this.vertx = vertx;
    this.kubeClient = kubeClient;
    this.natsTLSClient = natsTLSClient;  // Updated reference
    this.metadataVaultHandler = metadataVaultHandler;
    this.config = config;
    this.signer = signer;
    this.keyCache = keyCache;

    this.rotationConfig = RotationConfig.fromConfig( this.config );
    this.caEpoch        = new CAEpochUtil( rotationConfig );

    this.namespace = kubeClient.getNamespace();
    LOGGER.info( "CaRotatorVert initialized in namespace: {} (rotationConfig={}) - using NATS", namespace, rotationConfig );
  }

  @Override
  public void start() throws Exception
  {
    try
    {
      workerExecutor = vertx.createSharedWorkerExecutor( "ca-rotator-worker", 2, 360000 );

      startupInstant = Instant.now();
      long initialDelayMs = getInitialDelayMillis();

      startupTimerId = vertx.setTimer( initialDelayMs, id -> {
          startupTimerId = -1;
          LOGGER.info("Initial rotation delay elapsed ({} ms). Performing first rotation check.", initialDelayMs);
          doRotationCheck();
          timerId = vertx.setPeriodic( rotationConfig.getCheckInterval().toMillis(), t -> doRotationCheck() );
      });

      LOGGER.info("CaRotatorVert started with NATS support (initialDelayMs={} ms)", initialDelayMs);
    }
    catch( Exception e )
    {
      LOGGER.error( "Failed to start CaRotatorVert: {}", e.getMessage(), e );
      throw e;
    }
  }

  @Override
  public void stop() throws Exception
  {
    try
    {
      if( timerId != -1 )
      {
        vertx.cancelTimer( timerId );
        timerId = -1;
      }

      if( startupTimerId != -1 )
      {
        vertx.cancelTimer( startupTimerId );
        startupTimerId = -1;
      }

      if( workerExecutor != null )
        workerExecutor.close();
    }
    catch( Exception ignored )
    {
      LOGGER.warn( "Error shutting down CaRotatorVert: {}", ignored.getMessage() );
    }
    LOGGER.info("CaRotatorVert stopped");
  }

  private long getInitialDelayMillis()
  {
    try
    {
      String minEnv = System.getenv("CA_ROTATOR_INITIAL_DELAY_MINUTES");
      if( minEnv != null && !minEnv.isBlank() )
      {
        long mins = Long.parseLong(minEnv.trim());
        return Duration.ofMinutes(Math.max(0, mins)).toMillis();
      }

      String msEnv = System.getenv("CA_ROTATOR_INITIAL_DELAY_MS");
      if( msEnv != null && !msEnv.isBlank()) {
        long ms = Long.parseLong(msEnv.trim());
        return Math.max(0L, ms);
      }
    } catch (Exception e) {
      LOGGER.warn("Failed to parse CA_ROTATOR_INITIAL_DELAY env var, using default: {} ms", INITIAL_ROTATION_DELAY.toMillis());
    }
    return INITIAL_ROTATION_DELAY.toMillis();
  }

  /**
   * Enhanced rotation check with retry logic
   */
  private void doRotationCheck()
  {
    Instant now = Instant.now();

    long initialDelayMs = getInitialDelayMillis();
    if (startupInstant != null && now.isBefore(startupInstant.plusMillis(initialDelayMs))) {
      LOGGER.info("Initial rotation delay still in effect; skipping rotation check.");
      return;
    }

    long currentEpoch = caEpoch.epochNumberForInstant( now );
    boolean rotationNeeded = caEpoch.isRotationNeeded(now );
    Instant rotationTime   = caEpoch.epochRotationTime( currentEpoch );

    LOGGER.info("CA Epoch Check: epoch={} rotationNeeded={} nextRotation={}", currentEpoch, rotationNeeded, rotationTime);

    if( !rotationNeeded ) {
      LOGGER.debug("No CA rotation needed at this time.");
      return;
    }

    // Prevent performing rotation more than once for the same epoch.
    if (currentEpoch == lastRotatedEpoch) {
      LOGGER.info("Rotation for epoch {} already performed; skipping duplicate rotation.", currentEpoch);
      return;
    }

    performRotationWithRetry(currentEpoch, 0);
  }

  /**
   * Enhanced rotation with retry logic
   */
  private void performRotationWithRetry( long currentEpoch, int attemptCount )
  {
    if( attemptCount >= MAX_ROTATION_RETRIES )
    {
      LOGGER.error( "Maximum rotation attempts ({}) exceeded for epoch {}", MAX_ROTATION_RETRIES, currentEpoch );
      CaRotationWindowManager.markRotationEnd();
      return;
    }

    // Enhanced start logging and window management
    if( attemptCount == 0 )
    {
      LOGGER.info( "=== STARTING CA ROTATION PROCESS WITH NATS ===" );
      LOGGER.info( "CA Rotation Start - Epoch: {}, Time: {}", currentEpoch, Instant.now() );
      LOGGER.info( "Rotation will affect all NATS connections in metadata service" );

      // Set a longer rotation window for complex rotations
      CaRotationWindowManager.setRotationWindow( Duration.ofMinutes( 5 ) );
      CaRotationWindowManager.markRotationStart();
      LOGGER.info( "CA rotation window activated - handshake errors will be suppressed" );
    }

    LOGGER.info( "CA Rotation Progress - Epoch: {}, Attempt: {}/{}", currentEpoch, attemptCount + 1, MAX_ROTATION_RETRIES );

    performRotation().compose( newBundle -> {
      return buildPublishedBundle( newBundle ).compose( mergedBundle -> {
        return notifyLocalClientsWithValidation( mergedBundle ).compose( v -> {
          return publishCARotationEventWithRetry( "NATS", mergedBundle, 0 );  // Changed from "Pulsar"
        } );
      } );
    } ).onSuccess( result -> {
      if( result != null )
      {
        lastRotatedEpoch = currentEpoch;
        LOGGER.info( "Successfully completed CA rotation for epoch {} with NATS", currentEpoch );

        // Keep rotation window active for a bit longer to allow all connections
        // to stabilize
        vertx.setTimer( 60000, id -> { // 1 minute additional grace period
          CaRotationWindowManager.markRotationEnd();
          LOGGER.info( "CA rotation window ended for epoch {}", currentEpoch );
        } );
      } else
      {
        LOGGER.info( "Rotation workflow completed without publishing a CaBundle; not marking epoch as rotated." );
        CaRotationWindowManager.markRotationEnd();
      }
    } ).onFailure( err -> {
      String errorMsg = String.format( "CA rotation attempt %d failed for epoch %d: %s", attemptCount + 1, currentEpoch, err.getMessage() );

      // Use rotation-aware logging for rotation failures
      if( CaRotationWindowManager.isRotationRelatedError( err.getMessage() ) )
      {
        LOGGER.warn( "CA rotation failed with rotation-related error: {}", errorMsg );
      } else
      {
        LOGGER.error( "CA rotation failed with unexpected error: {}", errorMsg, err );
      }

      // Don't end rotation window on retry - keep it active
      if( attemptCount >= MAX_ROTATION_RETRIES - 1 )
      {
        // Only end on final failure
        CaRotationWindowManager.markRotationEnd();
      }

      // Schedule retry with exponential backoff
      long retryDelayMs = ROTATION_RETRY_DELAY.toMillis() * ( 1L << attemptCount );
      vertx.setTimer( retryDelayMs, id -> {
        LOGGER.info( "Retrying CA rotation for epoch {} after {} ms delay", currentEpoch, retryDelayMs );
        performRotationWithRetry( currentEpoch, attemptCount + 1 );
      } );
    } );
  }

  /**
   * Enhanced rotation with better error handling - Updated for NATS
   */
  private Future<String> performRotation() {
   LOGGER.info("Performing NATS CA rotation (snapshot-before-sign)...");

   return Future.<String>future(promise -> {
     // 1) Pre-collect existing chain snapshot BEFORE generating CSR
     metadataVaultHandler.preCollectExistingCertificates(NATS_PKI_MOUNT, VAULT_ROOT_CA_PATH)  // Changed mount
       .onFailure(preErr -> {
         LOGGER.warn("Pre-collection failed, continuing with empty snapshot: {}", preErr.getMessage());
         MetadataVaultHandler.ExistingCertificates emptySnapshot =
             new MetadataVaultHandler.ExistingCertificates(new ArrayList<>(), null);
         // proceed using empty snapshot
         proceedWithSnapshot(emptySnapshot, promise);
       })
       .onSuccess(existingSnapshot -> {
         // proceed with collected snapshot
         proceedWithSnapshot(existingSnapshot, promise);
       });
   });
  }

  // Helper to run the remaining async steps using a captured snapshot and complete the outer promise
  private void proceedWithSnapshot(MetadataVaultHandler.ExistingCertificates existingSnapshot, Promise<String> outerPromise) {
   // 2) Generate CSR
   metadataVaultHandler.generateIntermediateCsrInternal(NATS_PKI_MOUNT, "NATS Intermediate Authority", CERT_TYPE, CERT_STRENGTH)  // Changed description
     .onFailure(genErr -> {
       LOGGER.error("Failed to generate intermediate CSR", genErr);
       outerPromise.fail(genErr);
     })
     .onSuccess(csrWithKey -> {
       LOGGER.info("Generated intermediate CSR (keyId={})", csrWithKey.getKeyId());

       // 3) Sign CSR with root (pem_bundle)
       metadataVaultHandler.signCsrWithRoot(VAULT_ROOT_CA_PATH, csrWithKey.getCsr(), rotationConfig.buildCaTTLString())
         .onFailure(signErr -> {
           LOGGER.error("Failed to sign CSR with root", signErr);
           outerPromise.fail(signErr);
         })
         .onSuccess(signedCert -> {
           LOGGER.info("Received signed intermediate from root ({} chars)", signedCert != null ? signedCert.length() : 0);

           if (!isValidPemCertificate(signedCert)) {
             String msg = "Invalid PEM in signed certificate from root";
             LOGGER.error(msg);
             outerPromise.fail(msg);
             return;
           }

           // 4) Set the signed intermediate on the intermediate mount
           metadataVaultHandler.setIntermediateSignedCertificateInternal(NATS_PKI_MOUNT, signedCert)  // Changed mount
             .onFailure(setErr -> {
               LOGGER.error("Failed to set signed intermediate on PKI mount", setErr);
               outerPromise.fail(setErr);
             })
             .onSuccess(issuerId -> {
               LOGGER.info("Set intermediate signed certificate, issuerId={}", issuerId);

               // 5) Best-effort setDefaultIssuer (non-fatal), then wait and merge snapshot + new cert
               Future<Void> setDefaultFuture;
               if (issuerId != null) {
                 setDefaultFuture = metadataVaultHandler.setDefaultIssuer(NATS_PKI_MOUNT, issuerId)  // Changed mount
                   .recover(setDefaultErr -> {
                     LOGGER.warn("Unable to set default issuer (non-fatal): {}", setDefaultErr.getMessage());
                     return Future.succeededFuture((Void) null);
                   });
               } else {
                 // nothing to do
                 setDefaultFuture = Future.succeededFuture((Void) null);
               }

               setDefaultFuture
                 .onComplete(ignored -> {
                   // wait a short time for Vault to process
                   waitForProcessing(1500)
                     .onFailure(wErr -> {
                       LOGGER.warn("waitForProcessing failed: {}", wErr.getMessage());
                       // continue anyway
                     })
                     .onSuccess(v2 -> {
                       // Build merged bundle: new signedCert + existing snapshot
                       metadataVaultHandler.buildCompleteCABundleWithNew(existingSnapshot, signedCert)
                         .onSuccess(mergedBundle -> {
                           LOGGER.info("Built merged CA bundle ({} chars)", mergedBundle != null ? mergedBundle.length() : 0);
                           outerPromise.complete(mergedBundle);
                         })
                         .onFailure(buildErr -> {
                           LOGGER.error("Failed to build merged CA bundle", buildErr);
                           outerPromise.fail(buildErr);
                         });
                     });
                 });
             });
         });
     });
  }

  /**
   * Enhanced CA chain retrieval with fallback
   private Future<String> getCAChainWithFallback(String pkiMount) {
    return metadataVaultHandler.getCAChainEnhanced(pkiMount)
      .recover(err -> {
        LOGGER.warn("Enhanced CA chain retrieval failed, trying standard method: {}", err.getMessage());
        // Fallback to standard CA chain retrieval if enhanced fails
        return metadataVaultHandler.getCAChain(pkiMount)
          .recover(fallbackErr -> {
            LOGGER.error("Both enhanced and standard CA chain retrieval failed");
            return Future.failedFuture("Failed to retrieve CA chain: " + fallbackErr.getMessage());
          });
      });
  }
  */

  /**
   * Enhanced bundle building with better format handling
   */
  private Future<String> buildPublishedBundle(String newBundle) {
    return metadataVaultHandler.getCAChainEnhanced(VAULT_ROOT_CA_PATH)
      .recover(err -> {
        LOGGER.warn("Failed to get enhanced root CA chain, trying standard: {}", err.getMessage());
        return metadataVaultHandler.getCAChain(VAULT_ROOT_CA_PATH);
      })
      .compose(rootBundle -> workerExecutor.executeBlocking(() -> {
        try {
          List<String> parts = new ArrayList<>();

          // 1) existing intermediate(s) from local nats-ca-secret (if present)
          try {
            Secret existing = kubeClient.secrets().inNamespace(namespace).withName(LOCAL_CA_SECRET_NAME).get();
            if (existing != null && existing.getData() != null && existing.getData().containsKey(LOCAL_CA_SECRET_KEY)) {
              String existingB64 = existing.getData().get(LOCAL_CA_SECRET_KEY);
              if (existingB64 != null && !existingB64.isBlank()) {
                String existingPem = decodeSecretData(existingB64);
                if (existingPem != null && isValidPemBundle(existingPem)) {
                  List<String> existingCerts = splitPemCertificates(existingPem);
                  parts.addAll(existingCerts);
                  LOGGER.info("Found {} certificate(s) in existing {} secret", existingCerts.size(), LOCAL_CA_SECRET_NAME);
                } else {
                  LOGGER.warn("Existing secret contains invalid PEM data, skipping");
                }
              }
            } else {
              LOGGER.info("No existing {} secret found or empty", LOCAL_CA_SECRET_NAME);
            }
          } catch (Exception e) {
            LOGGER.warn("Error reading existing {} secret: {}", LOCAL_CA_SECRET_NAME, e.getMessage());
          }

          // 2) newly retrieved intermediate(s)
          if (newBundle != null && !newBundle.trim().isEmpty()) {
            if (isValidPemBundle(newBundle)) {
              List<String> newCerts = splitPemCertificates(newBundle);
              parts.addAll(newCerts);
              LOGGER.info("New bundle contains {} certificate(s)", newCerts.size());
            } else {
              LOGGER.error("New bundle contains invalid PEM data");
              throw new RuntimeException("Invalid PEM format in new certificate bundle");
            }
          }

          // 3) root bundle returned by Vault (may contain one or more anchors)
          if (rootBundle != null && !rootBundle.trim().isEmpty()) {
            String processedRootBundle = processVaultResponse(rootBundle);
            if (processedRootBundle != null && isValidPemBundle(processedRootBundle)) {
              List<String> rootCerts = splitPemCertificates(processedRootBundle);
              parts.addAll(rootCerts);
              LOGGER.info("Root bundle contains {} certificate(s)", rootCerts.size());
            } else {
              LOGGER.warn("Root bundle from VAULT_ROOT_CA_PATH is invalid or empty");
            }
          } else {
            LOGGER.warn("Root bundle from VAULT_ROOT_CA_PATH is empty");
          }

          // Deduplicate while preserving order
          LinkedHashMap<String,String> unique = new LinkedHashMap<>();
          for (String certPem : parts) {
            String norm = certPem.replaceAll("\\r","").trim();
            if (!norm.isEmpty() && !unique.containsKey(norm)) {
              unique.put(norm, norm);
            }
          }

          StringBuilder merged = new StringBuilder();
          for (String pem : unique.values()) {
            if (merged.length() > 0) merged.append("\n");
            merged.append(pem.trim());
          }

          String mergedPem = merged.toString();
          LOGGER.info("Built merged PEM bundle with {} certificate(s)", unique.size());
          return mergedPem;
        } catch (Exception e) {
          throw new RuntimeException("Failed to build published CA bundle: " + e.getMessage(), e);
        }
      }));
  }

  /**
   * Enhanced secret data decoding with format detection
   */
  private String decodeSecretData(String encodedData) {
    try {
      // First, try to decode as Base64
      byte[] decoded = Base64.getDecoder().decode(encodedData);
      String result = new String(decoded, StandardCharsets.UTF_8);
      
      // Verify it's valid PEM
      if (isValidPemBundle(result)) {
        return result;
      } else {
        LOGGER.warn("Decoded data is not valid PEM format");
        return null;
      }
    } catch (Exception e) {
      LOGGER.warn("Failed to decode secret data as Base64: {}", e.getMessage());
      
      // If Base64 decoding fails, check if it's already PEM
      if (isValidPemBundle(encodedData)) {
        LOGGER.info("Data appears to already be in PEM format");
        return encodedData;
      }
      
      return null;
    }
  }

  /**
   * Process Vault response to handle different formats
   */
  private String processVaultResponse(String vaultResponse) {
    if (vaultResponse == null || vaultResponse.trim().isEmpty()) {
      return null;
    }

    // Check if it's already valid PEM
    if (isValidPemBundle(vaultResponse)) {
      return vaultResponse;
    }

    // Try to decode as Base64 if it looks like Base64
    if (BASE64_PATTERN.matcher(vaultResponse.trim()).matches()) {
      try {
        byte[] decoded = Base64.getDecoder().decode(vaultResponse.trim());
        String decodedStr = new String(decoded, StandardCharsets.UTF_8);
        if (isValidPemBundle(decodedStr)) {
          LOGGER.info("Successfully decoded Vault response from Base64 to PEM");
          return decodedStr;
        }
      } catch (Exception e) {
        LOGGER.warn("Failed to decode Vault response as Base64: {}", e.getMessage());
      }
    }

    // Check for binary data indicators
    if (containsBinaryData(vaultResponse)) {
      LOGGER.warn("Vault response appears to contain binary data, cannot process");
      return null;
    }

    LOGGER.warn("Unable to process Vault response format");
    return null;
  }

  /**
   * Check if string contains binary data
   */
  private boolean containsBinaryData(String data) {
    if (data == null) return false;
    
    // Look for null bytes or other control characters that indicate binary data
    for (int i = 0; i < data.length(); i++) {
      char c = data.charAt(i);
      if (c == 0 || (c < 32 && c != '\n' && c != '\r' && c != '\t')) {
        return true;
      }
    }
    return false;
  }

  /**
   * Validate PEM certificate format
   */
  private boolean isValidPemCertificate(String pemData) {
    if (pemData == null || pemData.trim().isEmpty()) {
      return false;
    }
    
    return PEM_CERT_PATTERN.matcher(pemData).find();
  }

  /**
   * Validate PEM bundle format (may contain multiple certificates)
   */
  private boolean isValidPemBundle(String pemBundle) {
    if (pemBundle == null || pemBundle.trim().isEmpty()) {
      return false;
    }
    
    // Check if it contains at least one valid PEM certificate
    Matcher matcher = PEM_CERT_PATTERN.matcher(pemBundle);
    return matcher.find();
  }

  /**
   * Split a PEM bundle string into individual certificate PEM blocks.
   */
  private List<String> splitPemCertificates(String pemBundle) {
    List<String> certs = new ArrayList<>();
    if (pemBundle == null || pemBundle.trim().isEmpty()) return certs;

    Matcher m = PEM_CERT_PATTERN.matcher(pemBundle);
    while (m.find()) 
    {
      String block = m.group(0).trim();
      if (!block.isEmpty()) certs.add(block);
    }
    return certs;
  }

  /**
   * Enhanced local secret update with better error handling
   */
  private void updateLocalCaBundle( String caBundle ) 
  {
    try 
    {
      LOGGER.info("Updating local CA bundle secret {}/{}", namespace, LOCAL_CA_SECRET_NAME);

      // Validate bundle before updating
      if (!isValidPemBundle(caBundle)) {
        LOGGER.error("Cannot update local CA bundle: invalid PEM format");
        throw new RuntimeException("Invalid PEM format in CA bundle");
      }

      Secret secret = kubeClient.secrets().inNamespace(namespace).withName(LOCAL_CA_SECRET_NAME).get();

      if( secret == null ) 
      {
        LOGGER.warn("CA bundle secret {} not found in namespace {} - creating new secret",
                    LOCAL_CA_SECRET_NAME, namespace);

        Secret newSecret = new SecretBuilder()
          .withNewMetadata()
            .withName(LOCAL_CA_SECRET_NAME)
            .withNamespace(namespace)
          .endMetadata()
          .addToStringData(LOCAL_CA_SECRET_KEY, caBundle)
          .build();

        try 
        {
          kubeClient.secrets().inNamespace(namespace).resource(newSecret).create();
          LOGGER.info("Created new local CA bundle secret {}/{}", namespace, LOCAL_CA_SECRET_NAME);
        } 
        catch( KubernetesClientException kce ) 
        {
          if( kce.getCode() == 403 || (kce.getMessage() != null && kce.getMessage().toLowerCase().contains("forbidden"))) 
          {
            LOGGER.error("RBAC: insufficient permissions to create local secret '{}' in namespace '{}'. Grant create/patch/update on secrets to the rotator ServiceAccount. Error: {}",
                         LOCAL_CA_SECRET_NAME, namespace, kce.getMessage());
          } 
          else 
          {
            LOGGER.error("Failed to create local secret {}: {}", LOCAL_CA_SECRET_NAME, kce.getMessage(), kce);
          }
          throw kce;
        }
      } 
      else 
      {
        Secret updated = new SecretBuilder().withNewMetadata()
                                            .withName(LOCAL_CA_SECRET_NAME)
                                            .withNamespace(namespace)
                                            .endMetadata()
                                            .addToStringData(LOCAL_CA_SECRET_KEY, caBundle)
                                            .build();

        try 
        {
          kubeClient.secrets().inNamespace(namespace).resource( updated ).serverSideApply();
          LOGGER.info("Replaced existing local CA bundle secret {}/{}", namespace, LOCAL_CA_SECRET_NAME);
        }
        catch( KubernetesClientException kce ) 
        {
          if( kce.getCode() == 403 || (kce.getMessage() != null && kce.getMessage().toLowerCase().contains("forbidden")))
          {
            LOGGER.error( "RBAC: insufficient permissions to update local secret '{}' in namespace '{}'. Grant update/patch on secrets to the rotator ServiceAccount. Error: {}",
                          LOCAL_CA_SECRET_NAME, namespace, kce.getMessage());
          } 
          else 
          {
            LOGGER.error("Failed to update local CA bundle: {}", kce.getMessage(), kce);
          }
          throw kce;
        }
      }

    } 
    catch( Exception e ) 
    {
      LOGGER.error("Failed to update local CA bundle: {}", e.getMessage(), e);
      throw new RuntimeException("CA bundle update failed", e);
    }
  }

  /**
   * Enhanced local client notification with validation - Updated for NATS
   */
  private Future<Void> notifyLocalClientsWithValidation( String strBundle )
  {
    return workerExecutor.executeBlocking( () -> {
      // Validate bundle before updating anything
      if( !isValidPemBundle( strBundle ) )
      {
        throw new RuntimeException( "Invalid PEM bundle format - cannot notify clients" );
      }

      // 1. Update Kubernetes secret (for other consumers/restarts)
      updateLocalCaBundle( strBundle );
      return null;
    } ).compose( v -> {
      // 2. Build CaBundle and notify NatsTLSClient with enhanced validation
      if( natsTLSClient != null )
      {
        return buildCaBundle( "NATS", strBundle ).compose( caBundle -> {  // Changed from "Pulsar"
          // Enhanced rotation with connection pre-warming
          return performEnhancedCARotation( caBundle, strBundle );
        } );
      }
      return Future.succeededFuture();
    } );
  }

  /**
   * Enhanced CA rotation that minimizes connection disruption - Updated for NATS
   */
  private Future<Void> performEnhancedCARotation( CaBundle caBundle, String strBundle )
  {
    LOGGER.info( "Starting enhanced CA rotation with connection pre-warming for NATS" );

    return Future.succeededFuture().compose( v -> {
      // Step 1: Pre-warm new connections with new CA (if client supports it)
      try
      {
        boolean prewarmResult = false;
        try
        {
          Future<Boolean> prewarmFuture = preWarmConnectionsWithNewCA( strBundle );  // Custom method for NATS
          prewarmResult = prewarmFuture.toCompletionStage().toCompletableFuture().get( 5, TimeUnit.SECONDS );
        } catch( Exception e )
        {
          // Use rotation-aware logging for prewarm failures
          CaRotationWindowManager.logConnectionError( LOGGER, "Pre-warming failed, continuing with direct update", e );
          prewarmResult = false;
        }

        if( prewarmResult )
        {
          LOGGER.info( "Pre-warming connections with new CA bundle succeeded" );
        } else
        {
          LOGGER.info( "Pre-warming connections with new CA bundle did not succeed or was skipped; proceeding with direct update" );
        }

        // Give pre-warming time to settle if desired
        return waitForProcessing( 3000 );
      } catch( Exception e )
      {
        CaRotationWindowManager.logConnectionError( LOGGER, "Pre-warming failed, continuing with direct update", e );
        return Future.succeededFuture();
      }
    } ).compose( v -> {
      // Step 2: Update CA bundle on client
      try
      {
        Future<Void> updateFuture = natsTLSClient.handleCaBundleUpdate( caBundle );
        return updateFuture.recover( err -> {
          String errorMessage = "Failed to update NatsTLSClient CA bundle: " + err.getMessage();
          CaRotationWindowManager.logConnectionError( LOGGER, errorMessage, err );
          return Future.failedFuture( "NatsTLSClient CA update failed: " + err.getMessage() );
        } );
      } catch( Exception e )
      {
        String errorMessage = "Failed to update NatsTLSClient CA bundle: " + e.getMessage();
        CaRotationWindowManager.logConnectionError( LOGGER, errorMessage, e );
        return Future.failedFuture( "NatsTLSClient CA update failed: " + e.getMessage() );
      }
    } ).compose( v -> {
      // Step 3: Brief validation delay
      return waitForProcessing( 2000 );
    } ).compose( v -> {
      // Step 4: Optional connection health check with better error handling
      return performConnectionHealthCheck();
    } );
  }

  /**
   * Pre-warm connections with new CA bundle for NATS
   */
  private Future<Boolean> preWarmConnectionsWithNewCA(String caBundle) {
    // This is a placeholder - implement according to your NATS client capabilities
    // NATS may handle this differently than Pulsar
    LOGGER.debug("NATS connection pre-warming not implemented, returning false");
    return Future.succeededFuture(false);
  }
  
  /**
   * Simple connection health check for NATS
   */
  private Future<Void> performConnectionHealthCheck()
  {
    Promise<Void> promise = Promise.promise();

    // 5 second timeout for health check
    long timerId = vertx.setTimer( 5000, id -> 
    {
      LOGGER.debug( "Connection health check timed out - assuming success during rotation window" );
      promise.tryComplete();
    });

    try
    {
      // Check if NATS client is healthy
      boolean isHealthy = natsTLSClient.isHealthy();
      vertx.cancelTimer( timerId );
      
      if( isHealthy )
      {
        LOGGER.info( "NATS connection health check passed" );
        promise.tryComplete();
      } 
      else
      {
//        String message = "NATS connection health check failed, but continuing";
        LOGGER.debug( "NATS connection health check returned false during rotation - this is expected" );
        promise.tryComplete(); // Don't fail rotation for health check
      }
    } 
    catch( Exception e )
    {
      vertx.cancelTimer( timerId );
      CaRotationWindowManager.logConnectionError( LOGGER, "Health check failed, continuing anyway", e );
      promise.complete();
    }

    return promise.future();
  }
  
  /**
   * Enhanced CA rotation event publishing with retry - Updated for NATS
   */
  private Future<String> publishCARotationEventWithRetry( String serverId, String caBundle, int attemptCount )
  {
    if (attemptCount >= MAX_ROTATION_RETRIES) {
      return Future.failedFuture("Maximum publish attempts exceeded");
    }

    return generateSignedMessage( serverId, caBundle )
      .compose( signedMsg ->
      {
        try
        {
          byte[] signedBytes = SignedMessage.serialize( signedMsg );
          if( signedBytes == null || signedBytes.length == 0 )
          {
            return Future.failedFuture( "Failed to serialize SignedMessage for CA bundle" );
          }

          return natsTLSClient.publish( ServiceCoreIF.MetaDataClientCaCertStream, signedBytes )  // Updated subject naming
            .compose(v -> {
              LOGGER.info( "Published SignedMessage for CA rotation event to NATS subject: {}", ServiceCoreIF.MetaDataClientCaCertStream );
              return Future.succeededFuture("success");  // Return success indicator
            });
        }
        catch( Exception e )
        {
          String errMsg = "Error publishing CaBundle. Error = " + e.getMessage();
          LOGGER.error( errMsg, e );
          return Future.failedFuture(errMsg);
        }
      })
      .recover( err -> {
        LOGGER.warn( "Failed to publish CA rotation event (attempt {}): {}", attemptCount + 1, err.getMessage() );
        
        if (attemptCount < MAX_ROTATION_RETRIES - 1) {
          long retryDelayMs = 5000 * (attemptCount + 1); // Progressive delay
          
          Promise<String> retryPromise = Promise.promise();
          vertx.setTimer(retryDelayMs, id -> {
            LOGGER.info("Retrying CA rotation event publish (attempt {})", attemptCount + 2);
            publishCARotationEventWithRetry(serverId, caBundle, attemptCount + 1)
              .onComplete(retryPromise);
          });
          
          return retryPromise.future();
        } else {
          return Future.failedFuture("Failed to publish CA rotation event after " + MAX_ROTATION_RETRIES + " attempts");
        }
      });
  }

  /**
   * Generate SignedMessage for CA bundle
   */
  private Future<SignedMessage> generateSignedMessage( String serverId, String caBundle )
  {
    LOGGER.info( "Generating CA Bundle SignedMessage for server: {}", serverId );

    return buildCaBundle( serverId, caBundle )
      .compose( bundle ->
        workerExecutor.executeBlocking( () ->
        {
          byte[] serializedBundle = CaBundle.serialize( bundle );
          if( serializedBundle == null || serializedBundle.length == 0 )
          {
            throw new RuntimeException( "Failed to serialize CaBundle for server: " + serverId );
          }
          return serializedBundle;
        })
      )
      .compose( serializedBundle ->
        getMetadataSigningKey()
          .compose( signKey ->
            signer.sign( serializedBundle, signKey )
              .compose( signature ->
                workerExecutor.executeBlocking( () ->
                {
                  long keyEpoch = KeyEpochUtil.epochNumberForInstant( Instant.now() );
                  List<TopicKey> keyList = keyCache.getValidTopicKeysSorted( ServiceCoreIF.MetaDataClientCaCertStream );  // Updated
                  TopicKey topicKey = null;

                  for( TopicKey key : keyList )
                  {
                    if( keyEpoch == key.getEpochNumber() )
                    {
                      topicKey = key;
                      break;
                    }
                  }

                  if( topicKey == null )
                  {
                    String errMsg = "Generating SignedMessage process could not obtain an encryption key.";
                    LOGGER.error( errMsg );
                    throw new RuntimeException( errMsg );
                  }

                  EncryptedData encData = aesCrypto.encrypt( serializedBundle, topicKey.getKeyData() );
                  if( encData == null || encData.getCiphertext() == null || encData.getCiphertext().length == 0 )
                  {
                    throw new RuntimeException( "Failed to encrypt CaBundle for server: " + serverId );
                  }

                  LOGGER.info( "Successfully generated and encrypted CaBundle for server: {}", serverId );

                  SignedMessage signedMsg = new SignedMessage(
                    serverId + Instant.now().toString(),
                    "CaBundle",
                    "metadata",
                    signKey.getEpochNumber(),
                    Instant.now(),
                    signature,
                    ServiceCoreIF.MetaDataClientCaCertStream,  // Updated
                    topicKey.getKeyId(),
                    "CaBundle",
                    encData.serialize()
                  );
                  return signedMsg;
                })
              )
            )
      )
      .onFailure( err ->
      {
        LOGGER.error( "Failed to process CA Bundle for server: {}", serverId, err );
      });
  }

  /**
   * Build CaBundle message
   */
  private Future<CaBundle> buildCaBundle(String serverId, String caBundle)
  {
    return workerExecutor.executeBlocking(() ->
    {
      Instant timestamp  = Instant.now();
      String  caVersion  = timestamp.toString();
      long    caEpochNum = caEpoch.epochNumberForInstant( timestamp );

      CaBundle bundle = new CaBundle( serverId, timestamp, caEpochNum, ServiceCoreIF.CaRotationEvent, caBundle, caVersion);
      return bundle;
    });
  }

  /**
   * Get metadata signing key from event bus
   */
  public Future<DilithiumKey> getMetadataSigningKey()
  {
    return vertx.eventBus().<Buffer> request( ServicesACLWatcherVert.METADATA__SIGNING_KEY_ADDR, "metadata" )
      .compose( msg ->
      {
        try
        {
          DilithiumKey key = DilithiumKey.deSerialize( msg.body().getBytes(), "transport" );
          return Future.succeededFuture( key );
        }
        catch( Exception e )
        {
          return Future.failedFuture( e );
        }
      });
  }

  private Future<Void> waitForProcessing(long delayMs) {
    Promise<Void> p = Promise.promise();
    vertx.setTimer(delayMs, id -> p.complete());
    return p.future();
  }
}