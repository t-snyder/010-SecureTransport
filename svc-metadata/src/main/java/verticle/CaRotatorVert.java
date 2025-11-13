package verticle;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;

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
import core.utils.CAEpochUtil;
import core.utils.KeyEpochUtil;

import handler.MetadataVaultHandler;
import helper.MetadataConfig;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Enhanced CA Rotator with issuer cleanup and reliable issuer detection
 */
public class CaRotatorVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger(CaRotatorVert.class);

  private static final String VAULT_ROOT_CA_PATH = "pki";
  private static final String NATS_PKI_MOUNT = "nats_int";

  private static final String CERT_TYPE = "rsa";
  private static final int CERT_STRENGTH = 4096;

  private static final String LOCAL_CA_SECRET_NAME = "nats-ca-secret";
  private static final String LOCAL_CA_SECRET_KEY = "ca.crt";

  private static final Pattern PEM_CERT_PATTERN = Pattern.compile(
    "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----"
  );

  private KubernetesClient kubeClient;
  private NatsTLSClient natsTLSClient;
  private WorkerExecutor workerExecutor;
  private MetadataVaultHandler metadataVaultHandler;

  private final MetadataConfig config;
  private final DilithiumService signer;
  private final KeySecretManager keyCache;
  private final AesGcmHkdfCrypto aesCrypto = new AesGcmHkdfCrypto();
  private final CAEpochUtil caEpochUtil = new CAEpochUtil();

  private String namespace;
  private long timerId = -1;
  private long startupTimerId = -1;
  private Instant startupInstant;

  private static final Duration INITIAL_ROTATION_DELAY = Duration.ofMinutes(3);
  private static final long     initialDelayMs         = INITIAL_ROTATION_DELAY.toMillis();

  private volatile long lastRotatedEpoch = Long.MIN_VALUE;

  private static final int MAX_ROTATION_RETRIES = 3;
  private static final Duration ROTATION_RETRY_DELAY = Duration.ofSeconds(30);

  public CaRotatorVert(Vertx vertx, KubernetesClient kubeClient, NatsTLSClient natsTLSClient,
                       MetadataVaultHandler metadataVaultHandler, MetadataConfig config,
                       DilithiumService signer, KeySecretManager keyCache)
  {
    this.vertx = vertx;
    this.kubeClient = kubeClient;
    this.natsTLSClient = natsTLSClient;
    this.metadataVaultHandler = metadataVaultHandler;
    this.config = config;
    this.signer = signer;
    this.keyCache = keyCache;

    this.namespace = kubeClient.getNamespace();
    LOGGER.info("CaRotatorVert initialized in namespace: {}", namespace);
  }

  @Override
  public void start() throws Exception
  {
    try
    {
      workerExecutor = vertx.createSharedWorkerExecutor("ca-rotator-worker", 2, 360000);

      // Log configuration on startup
      LOGGER.info("=== CA ROTATOR CONFIGURATION ===");
      LOGGER.info(caEpochUtil.getConfigDescription());
//      LOGGER.info("Initial delay: {} minutes", getInitialDelayMillis() / 60000);
      
      // Show rotation schedule for debugging
      Instant now = Instant.now();
      long currentEpoch = caEpochUtil.epochNumberForInstant(now);
      LOGGER.info("Current time: {}", now);
      LOGGER.info("Current epoch: {}", currentEpoch);
      LOGGER.info("Epoch start: {}", caEpochUtil.epochStart(currentEpoch));
      LOGGER.info("Next rotation time: {}", caEpochUtil.epochRotationTime(currentEpoch));
      LOGGER.info("Cert expiry for this epoch: {}", caEpochUtil.epochExpiry(currentEpoch));
      LOGGER.info("Prune time for this epoch: {}", caEpochUtil.epochPruneTime(currentEpoch));
      LOGGER.info("Check interval: {} minutes", caEpochUtil.getCheckInterval().toMinutes());

      startupInstant      = Instant.now();
  
      LOGGER.info( "Initial Delay ms set to: " + initialDelayMs );
      LOGGER.info("================================");

      startupTimerId = vertx.setTimer( initialDelayMs, id -> 
      {
        startupTimerId = -1;
        LOGGER.info("Initial rotation delay elapsed ({} ms). Performing first rotation check.", initialDelayMs);
        doRotationCheck();

        timerId = vertx.setPeriodic(caEpochUtil.getCheckInterval().toMillis(), t -> doRotationCheck());
      });

      LOGGER.info("CaRotatorVert started with NATS support (initialDelayMs={} ms)", initialDelayMs);
      LOGGER.info("Periodic rotation checks will run every {} milliseconds", caEpochUtil.getCheckInterval().toMillis());
    }
    catch (Exception e)
    {
      LOGGER.error("Failed to start CaRotatorVert: {}", e.getMessage(), e);
      throw e;
    }
  }
  
  /**
  @Override
  public void start() throws Exception
  {
    try
    {
      workerExecutor = vertx.createSharedWorkerExecutor("ca-rotator-worker", 2, 360000);

      startupInstant = Instant.now();
      long initialDelayMs = getInitialDelayMillis();

      startupTimerId = vertx.setTimer(initialDelayMs, id -> {
        startupTimerId = -1;
        LOGGER.info("Initial rotation delay elapsed ({} ms). Performing first rotation check.", initialDelayMs);
        doRotationCheck();
        timerId = vertx.setPeriodic(caEpochUtil.getCheckInterval().toMillis(), t -> doRotationCheck());
      });

      LOGGER.info("CaRotatorVert started with NATS support (initialDelayMs={} ms)", initialDelayMs);
    }
    catch (Exception e)
    {
      LOGGER.error("Failed to start CaRotatorVert: {}", e.getMessage(), e);
      throw e;
    }
  }
*/
  
  @Override
  public void stop() throws Exception
  {
    try
    {
      if (timerId != -1)
      {
        vertx.cancelTimer(timerId);
        timerId = -1;
      }

      if (startupTimerId != -1)
      {
        vertx.cancelTimer(startupTimerId);
        startupTimerId = -1;
      }

      if (workerExecutor != null)
        workerExecutor.close();
    }
    catch (Exception ignored)
    {
      LOGGER.warn("Error shutting down CaRotatorVert: {}", ignored.getMessage());
    }
    LOGGER.info("CaRotatorVert stopped");
  }

/**  
  private long getInitialDelayMillis()
  {
    try
    {
      String minEnv = System.getenv("CA_ROTATOR_INITIAL_DELAY_MINUTES");
      if (minEnv != null && !minEnv.isBlank())
      {
        long mins = Long.parseLong(minEnv.trim());
        return Duration.ofMinutes(Math.max(0, mins)).toMillis();
      }

      String msEnv = System.getenv("CA_ROTATOR_INITIAL_DELAY_MS");
      if (msEnv != null && !msEnv.isBlank())
      {
        long ms = Long.parseLong(msEnv.trim());
        return Math.max(0L, ms);
      }
    }
    catch (Exception e)
    {
      LOGGER.warn("Failed to parse CA_ROTATOR_INITIAL_DELAY env var, using default: {} ms", 
        INITIAL_ROTATION_DELAY.toMillis());
    }
    return INITIAL_ROTATION_DELAY.toMillis();
  }
*/
  /**
   * Check if rotation is needed
   */
  private void doRotationCheck()
  {
    Instant now = Instant.now();

    if (startupInstant != null && now.isBefore(startupInstant.plusMillis(initialDelayMs)))
    {
      LOGGER.info("Initial rotation delay still in effect; skipping rotation check.");
      return;
    }

    long currentEpoch = caEpochUtil.epochNumberForInstant(now);
    Instant currentEpochStart = caEpochUtil.epochStart(currentEpoch);
    Instant nextEpochStart = caEpochUtil.epochStart(currentEpoch + 1);
    
    // Enhanced logging - always use INFO level for rotation checks
    LOGGER.info("=== CA ROTATION CHECK ===");
    LOGGER.info("Current time: {}", now);
    LOGGER.info("Current epoch: {}", currentEpoch);
    LOGGER.info("Current epoch started: {}", currentEpochStart);
    LOGGER.info("Next epoch starts: {}", nextEpochStart);
    LOGGER.info("Last rotated epoch: {}", lastRotatedEpoch);
    
    // Check if we need to rotate for the current epoch
    boolean rotationNeeded = (currentEpoch > lastRotatedEpoch);
    
    LOGGER.info("Rotation needed: {}", rotationNeeded);
    
    // Show time until next rotation
    if (!rotationNeeded) {
      Duration timeUntilRotation = Duration.between(now, nextEpochStart);
      LOGGER.info("Time until next epoch: {} minutes {} seconds", 
        timeUntilRotation.toMinutes(), timeUntilRotation.toSecondsPart());
    }
    LOGGER.info("========================");

    if (!rotationNeeded)
    {
      LOGGER.info("No CA rotation needed - already rotated for epoch {}", currentEpoch);
      return;
    }

    LOGGER.info("Starting rotation for epoch {}", currentEpoch);
    performRotationWithRetry(currentEpoch, 0);
  }
  
  /**
   * Enhanced rotation with retry logic and grace period-based issuer cleanup
   */
  private void performRotationWithRetry(long currentEpoch, int attemptCount)
  {
    if (attemptCount >= MAX_ROTATION_RETRIES)
    {
      LOGGER.error("Maximum rotation attempts ({}) exceeded for epoch {}", MAX_ROTATION_RETRIES, currentEpoch);
      return;
    }

    if (attemptCount == 0)
    {
      LOGGER.info("=== STARTING CA ROTATION PROCESS ===");
      LOGGER.info("CA Rotation Start - Epoch: {}, Time: {}", currentEpoch, Instant.now());
      LOGGER.info("Certificate TTL: {}, Grace Period: {}", 
        caEpochUtil.getCertificateTTL().toMinutes() + "m",
        caEpochUtil.getGracePeriod().toMinutes() + "m");
    }

    LOGGER.info("CA Rotation Progress - Epoch: {}, Attempt: {}/{}", 
      currentEpoch, attemptCount + 1, MAX_ROTATION_RETRIES);

    performRotation()
      .<String>compose(newBundle -> buildPublishedBundle(newBundle))
      .<String>compose(mergedBundle -> persistLocalCaBundle(mergedBundle).<String>map(ignored -> mergedBundle))
      .<CaBundle>compose(mergedBundle -> buildCaBundle("NATS", mergedBundle))
      .<CaBundle>compose(caBundle -> {
        LOGGER.info("Storing CA bundle in Vault for epoch {}", currentEpoch);
        return metadataVaultHandler.putCaBundle("NATS", currentEpoch, caBundle)
          .<CaBundle>map(ignored -> caBundle)
          .recover(err -> {
            LOGGER.error("Failed to store CA bundle in Vault (non-fatal): {}", err.getMessage(), err);
            return Future.succeededFuture(caBundle);
          });
      })
      .<CaBundle>compose(caBundle -> publishCARotationEventWithRetry("NATS", caBundle.getCaBundle(), 0).<CaBundle>map(ignored -> caBundle))
      .<CaBundle>compose(caBundle -> {
        try
        {
          return natsTLSClient.handleCaBundleUpdate(caBundle)
            .recover(err -> {
              LOGGER.warn("Local NATS client CA update failed (non-fatal): {}", err.getMessage());
              return Future.succeededFuture();
            })
            .<CaBundle>map(ignored -> caBundle);
        }
        catch (Exception e)
        {
          LOGGER.warn("Local NATS client CA update threw an exception (non-fatal): {}", e.getMessage());
          return Future.succeededFuture(caBundle);
        }
      })
      // ENHANCED: Prune expired issuers based on grace period
      .<CaBundle>compose(caBundle -> {
        LOGGER.info("Pruning expired issuers from PKI mount (grace period: {} minutes)", 
          caEpochUtil.getGracePeriod().toMinutes());
        
        return metadataVaultHandler.pruneExpiredIssuers(NATS_PKI_MOUNT, caEpochUtil)
          .<CaBundle>map(deletedCount -> {
            LOGGER.info("Pruned {} expired issuers from PKI mount", deletedCount);
            return caBundle;
          })
          .recover(err -> {
            LOGGER.warn("Failed to prune expired issuers (non-fatal): {}", err.getMessage());
            return Future.succeededFuture(caBundle);
          });
      })
      // Prune old CA bundles
      .<CaBundle>compose(caBundle -> {
        int keepLastN = caEpochUtil.getMaxCertsInBundle();
        LOGGER.info("Pruning old CA bundles, keeping last {} bundles", keepLastN);
        
        return metadataVaultHandler.pruneOldCaBundles("NATS", keepLastN)
          .<CaBundle>map(deletedCount -> {
            LOGGER.info("Pruned {} old CA bundles", deletedCount);
            return caBundle;
          })
          .recover(err -> {
            LOGGER.warn("Failed to prune old CA bundles (non-fatal): {}", err.getMessage());
            return Future.succeededFuture(caBundle);
          });
      })
      .onSuccess(result -> {
        lastRotatedEpoch = currentEpoch;
        LOGGER.info("=== COMPLETED CA ROTATION FOR EPOCH {} ===", currentEpoch);
        LOGGER.info("Next rotation scheduled at: {}", caEpochUtil.epochRotationTime(currentEpoch + 1));
      })
      .onFailure(err -> {
        String errorMsg = String.format("CA rotation attempt %d failed for epoch %d: %s", 
          attemptCount + 1, currentEpoch, err.getMessage());
        LOGGER.error(errorMsg, err);

        long retryDelayMs = ROTATION_RETRY_DELAY.toMillis() * (1L << attemptCount);
        vertx.setTimer(retryDelayMs, id -> {
          LOGGER.info("Retrying CA rotation for epoch {} after {} ms delay", currentEpoch, retryDelayMs);
          performRotationWithRetry(currentEpoch, attemptCount + 1);
        });
      });
  }  
  
  /**
   * Enhanced rotation with retry logic and issuer cleanup
  private void performRotationWithRetry(long currentEpoch, int attemptCount)
  {
    if (attemptCount >= MAX_ROTATION_RETRIES)
    {
      LOGGER.error("Maximum rotation attempts ({}) exceeded for epoch {}", MAX_ROTATION_RETRIES, currentEpoch);
      return;
    }

    if (attemptCount == 0)
    {
      LOGGER.info("=== STARTING CA ROTATION PROCESS WITH NATS ===");
      LOGGER.info("CA Rotation Start - Epoch: {}, Time: {}", currentEpoch, Instant.now());
    }

    LOGGER.info("CA Rotation Progress - Epoch: {}, Attempt: {}/{}", 
      currentEpoch, attemptCount + 1, MAX_ROTATION_RETRIES);

    performRotation()
      .compose(newBundle -> buildPublishedBundle(newBundle))
      .compose(mergedBundle -> persistLocalCaBundle(mergedBundle).map(ignored -> mergedBundle))
      .compose(mergedBundle -> buildCaBundle("NATS", mergedBundle))
      .compose(caBundle -> {
        LOGGER.info("Storing CA bundle in Vault for epoch {}", currentEpoch);
        return metadataVaultHandler.putCaBundle("NATS", currentEpoch, caBundle)
          .map(ignored -> caBundle)
          .recover(err -> {
            LOGGER.error("Failed to store CA bundle in Vault (non-fatal): {}", err.getMessage(), err);
            return Future.succeededFuture(caBundle);
          });
      })
      .compose(caBundle -> publishCARotationEventWithRetry("NATS", caBundle.getCaBundle(), 0).map(ignored -> caBundle))
      .compose(caBundle -> {
        try
        {
          return natsTLSClient.handleCaBundleUpdate(caBundle)
            .recover(err -> {
              LOGGER.warn("Local NATS client CA update failed (non-fatal): {}", err.getMessage());
              return Future.succeededFuture();
            })
            .map(ignored -> caBundle);
        }
        catch (Exception e)
        {
          LOGGER.warn("Local NATS client CA update threw an exception (non-fatal): {}", e.getMessage());
          return Future.succeededFuture(caBundle);
        }
      })
      // ENHANCED: Prune old issuers from PKI mount
      .compose(caBundle -> {
        int keepLastN = caEpochUtil.getMaxCertsInBundle();
        LOGGER.info("Pruning old issuers from PKI mount, keeping last {}", keepLastN);
        
        return metadataVaultHandler.pruneOldIssuers(NATS_PKI_MOUNT, keepLastN)
          .map(deletedCount -> {
            LOGGER.info("Pruned {} old issuers from PKI mount", deletedCount);
            return caBundle;
          })
          .recover(err -> {
            LOGGER.warn("Failed to prune old issuers (non-fatal): {}", err.getMessage());
            return Future.succeededFuture(caBundle);
          });
      })
      // Prune old CA bundles
      .compose(caBundle -> {
        int keepLastN = caEpochUtil.getMaxCertsInBundle();
        LOGGER.info("Pruning old CA bundles, keeping last {} bundles", keepLastN);
        
        return metadataVaultHandler.pruneOldCaBundles("NATS", keepLastN)
          .map(deletedCount -> {
            LOGGER.info("Pruned {} old CA bundles", deletedCount);
            return caBundle;
          })
          .recover(err -> {
            LOGGER.warn("Failed to prune old CA bundles (non-fatal): {}", err.getMessage());
            return Future.succeededFuture(caBundle);
          });
      })
      .onSuccess(result -> {
        lastRotatedEpoch = currentEpoch;
        LOGGER.info("Successfully completed CA rotation and storage for epoch {}", currentEpoch);
      })
      .onFailure(err -> {
        String errorMsg = String.format("CA rotation attempt %d failed for epoch %d: %s", 
          attemptCount + 1, currentEpoch, err.getMessage());
        LOGGER.error(errorMsg, err);

        long retryDelayMs = ROTATION_RETRY_DELAY.toMillis() * (1L << attemptCount);
        vertx.setTimer(retryDelayMs, id -> {
          LOGGER.info("Retrying CA rotation for epoch {} after {} ms delay", currentEpoch, retryDelayMs);
          performRotationWithRetry(currentEpoch, attemptCount + 1);
        });
      });
  }
   */

  /**
   * Perform rotation with snapshot-before-sign approach
   */
  private Future<String> performRotation()
  {
    LOGGER.info("Performing NATS CA rotation (snapshot-before-sign)...");

    return Future.<String>future(promise -> {
      metadataVaultHandler.preCollectExistingCertificates(NATS_PKI_MOUNT, VAULT_ROOT_CA_PATH)
        .onFailure(preErr -> {
          LOGGER.warn("Pre-collection failed, continuing with empty snapshot: {}", preErr.getMessage());
          MetadataVaultHandler.ExistingCertificates emptySnapshot =
            new MetadataVaultHandler.ExistingCertificates(new ArrayList<>(), null);
          proceedWithSnapshot(emptySnapshot, promise);
        })
        .onSuccess(existingSnapshot -> {
          proceedWithSnapshot(existingSnapshot, promise);
        });
    });
  }

  /**
   * Proceed with snapshot using NEW key generation for each rotation
   * 
   * With internal key storage, OpenBao automatically associates the signed certificate
   * with the key that generated the CSR. If the import succeeds, the association is guaranteed.
   */
  private void proceedWithSnapshot(MetadataVaultHandler.ExistingCertificates existingSnapshot, 
                                    Promise<String> outerPromise)
  {
    // Generate unique key name for this rotation
    Instant now = Instant.now();
    long currentEpoch = caEpochUtil.epochNumberForInstant(now);
    String keyName = "nats-int-key-" + currentEpoch;
    
    LOGGER.info("Generating NEW internal key and CSR for epoch {} with name: {}", currentEpoch, keyName);
    
    // Generate key AND CSR in one operation to ensure they match
    // Using internal storage - private key never leaves OpenBao
    metadataVaultHandler.generateNewKeyAndCsr(
        NATS_PKI_MOUNT, 
        "NATS Intermediate Authority",
        keyName,
        CERT_TYPE, 
        CERT_STRENGTH
      )
      .onFailure(genErr -> {
        LOGGER.error("Failed to generate new key and CSR", genErr);
        outerPromise.fail(genErr);
      })
      .onSuccess(csrWithKey -> {
        LOGGER.info("Generated NEW key and intermediate CSR (keyId={})", csrWithKey.getKeyId());

        // Verify key ID is not null
        if (csrWithKey.getKeyId() == null || csrWithKey.getKeyId().isEmpty()) {
          String msg = "Failed to get key ID from CSR generation";
          LOGGER.error(msg);
          outerPromise.fail(msg);
          return;
        }

        // Sign CSR with root CA
        metadataVaultHandler.signCsrWithRoot(VAULT_ROOT_CA_PATH, csrWithKey.getCsr(), 
                                             caEpochUtil.buildCaTTLString())
          .onFailure(signErr -> {
            LOGGER.error("Failed to sign CSR with root", signErr);
            outerPromise.fail(signErr);
          })
          .onSuccess(signedCert -> {
            LOGGER.info("Received signed intermediate from root ({} chars)", 
              signedCert != null ? signedCert.length() : 0);

            if (!isValidPemCertificate(signedCert))
            {
              String msg = "Invalid PEM in signed certificate from root";
              LOGGER.error(msg);
              outerPromise.fail(msg);
              return;
            }

            // Import signed cert - automatically associates with the internal key
            metadataVaultHandler.setIntermediateSignedCertificateInternal(NATS_PKI_MOUNT, signedCert)
              .onFailure(setErr -> {
                LOGGER.error("Failed to set signed intermediate on PKI mount", setErr);
                outerPromise.fail(setErr);
              })
              .onSuccess(issuerId -> {
                LOGGER.info("✅ Imported signed certificate as issuer: {}", issuerId);
                LOGGER.info("   Associated with internal key: {}", csrWithKey.getKeyId());
                LOGGER.info("   Key name: {}", keyName);

                // Set default issuer
                Future<Void> setDefaultFuture;
                if (issuerId != null && !issuerId.isEmpty())
                {
                  LOGGER.info("Setting default issuer to: {}", issuerId);
                  setDefaultFuture = metadataVaultHandler.setDefaultIssuer(NATS_PKI_MOUNT, issuerId)
                    .recover(setDefaultErr -> {
                      LOGGER.warn("Unable to set default issuer (non-fatal): {}", setDefaultErr.getMessage());
                      return Future.succeededFuture((Void) null);
                    });
                }
                else
                {
                  LOGGER.warn("⚠️  No issuer ID found - default issuer not set");
                  setDefaultFuture = Future.succeededFuture((Void) null);
                }

                setDefaultFuture
                  .compose(ignored -> waitForProcessing(1500))
                  .compose(v2 -> metadataVaultHandler.buildCompleteCABundleWithNew(existingSnapshot, signedCert))
                  .onSuccess(mergedBundle -> {
                    LOGGER.info("Built merged CA bundle ({} chars)", 
                      mergedBundle != null ? mergedBundle.length() : 0);
                    outerPromise.complete(mergedBundle);
                  })
                  .onFailure(buildErr -> {
                    LOGGER.error("Failed to build merged CA bundle", buildErr);
                    outerPromise.fail(buildErr);
                  });
              });
          });
      });
  }
  
  /**
   * Proceed with snapshot using NEW key generation for each rotation (CORRECTED)
  private void proceedWithSnapshot(MetadataVaultHandler.ExistingCertificates existingSnapshot, 
                                    Promise<String> outerPromise)
  {
    // Generate unique key name for this rotation
    Instant now = Instant.now();
    long currentEpoch = caEpochUtil.epochNumberForInstant(now);
    String keyName = "nats-int-key-" + currentEpoch;
    
    LOGGER.info("Generating NEW internal key and CSR for epoch {} with name: {}", currentEpoch, keyName);
    
    // CORRECTED: Generate key AND CSR in one operation to ensure they match
    metadataVaultHandler.generateNewKeyAndCsr(
        NATS_PKI_MOUNT, 
        "NATS Intermediate Authority",
        keyName,
        CERT_TYPE, 
        CERT_STRENGTH
      )
      .onFailure(genErr -> {
        LOGGER.error("Failed to generate new key and CSR", genErr);
        outerPromise.fail(genErr);
      })
      .onSuccess(csrWithKey -> {
        LOGGER.info("Generated NEW key and intermediate CSR (keyId={})", csrWithKey.getKeyId());

        // Verify key ID is not null
        if (csrWithKey.getKeyId() == null || csrWithKey.getKeyId().isEmpty()) {
          String msg = "Failed to get key ID from CSR generation";
          LOGGER.error(msg);
          outerPromise.fail(msg);
          return;
        }

        // Sign CSR with root
        metadataVaultHandler.signCsrWithRoot(VAULT_ROOT_CA_PATH, csrWithKey.getCsr(), 
                                             caEpochUtil.buildCaTTLString())
          .onFailure(signErr -> {
            LOGGER.error("Failed to sign CSR with root", signErr);
            outerPromise.fail(signErr);
          })
          .onSuccess(signedCert -> {
            LOGGER.info("Received signed intermediate from root ({} chars)", 
              signedCert != null ? signedCert.length() : 0);

            if (!isValidPemCertificate(signedCert))
            {
              String msg = "Invalid PEM in signed certificate from root";
              LOGGER.error(msg);
              outerPromise.fail(msg);
              return;
            }

            // Import signed cert (associates with the key automatically)
            metadataVaultHandler.setIntermediateSignedCertificateInternal(NATS_PKI_MOUNT, signedCert)
              .onFailure(setErr -> {
                LOGGER.error("Failed to set signed intermediate on PKI mount", setErr);
                outerPromise.fail(setErr);
              })
              .onSuccess(issuerId -> {
                LOGGER.info("Set intermediate signed certificate, issuerId={}, keyId={}", 
                  issuerId, csrWithKey.getKeyId());

                // Verify the issuer is using the correct key
                metadataVaultHandler.getIssuerInfo(NATS_PKI_MOUNT, issuerId)
                  .onSuccess(issuerInfo -> {
                    JsonObject data = issuerInfo.getJsonObject("data");
                    String issuerKeyId = data != null ? data.getString("key_id") : null;
                    
                    if (!csrWithKey.getKeyId().equals(issuerKeyId)) {
                      LOGGER.error("⚠️ KEY MISMATCH! Expected: {}, Got: {}", 
                        csrWithKey.getKeyId(), issuerKeyId);
                    } else {
                      LOGGER.info("✅ Verified issuer {} is using correct key {}", 
                        issuerId, issuerKeyId);
                    }
                  })
                  .onFailure(err -> {
                    LOGGER.warn("Could not verify issuer key (non-fatal): {}", err.getMessage());
                  });

                // Set default issuer
                Future<Void> setDefaultFuture;
                if (issuerId != null && !issuerId.isEmpty())
                {
                  LOGGER.info("Setting default issuer to: {}", issuerId);
                  setDefaultFuture = metadataVaultHandler.setDefaultIssuer(NATS_PKI_MOUNT, issuerId)
                    .recover(setDefaultErr -> {
                      LOGGER.warn("Unable to set default issuer (non-fatal): {}", setDefaultErr.getMessage());
                      return Future.succeededFuture((Void) null);
                    });
                }
                else
                {
                  LOGGER.warn("⚠️  No issuer ID found - default issuer not set");
                  setDefaultFuture = Future.succeededFuture((Void) null);
                }

                setDefaultFuture
                  .compose(ignored -> waitForProcessing(1500))
                  .compose(v2 -> metadataVaultHandler.buildCompleteCABundleWithNew(existingSnapshot, signedCert))
                  .onSuccess(mergedBundle -> {
                    LOGGER.info("Built merged CA bundle ({} chars)", 
                      mergedBundle != null ? mergedBundle.length() : 0);
                    outerPromise.complete(mergedBundle);
                  })
                  .onFailure(buildErr -> {
                    LOGGER.error("Failed to build merged CA bundle", buildErr);
                    outerPromise.fail(buildErr);
                  });
              });
          });
      });
  }
   */
  
  /**
   * Proceed with snapshot using NEW key generation for each rotation
  private void proceedWithSnapshot(MetadataVaultHandler.ExistingCertificates existingSnapshot, 
                                    Promise<String> outerPromise)
  {
    // Generate unique key name for this rotation
    Instant now = Instant.now();
    long currentEpoch = caEpochUtil.epochNumberForInstant(now);
    String keyName = "nats-int-key-" + currentEpoch;
    
    LOGGER.info("Generating NEW internal key for epoch {} with name: {}", currentEpoch, keyName);
    
    // Step 1: Generate new key
    metadataVaultHandler.generateNewKey(NATS_PKI_MOUNT, keyName, CERT_TYPE, CERT_STRENGTH)
      .onFailure(keyErr -> {
        LOGGER.error("Failed to generate new key", keyErr);
        outerPromise.fail(keyErr);
      })
      .onSuccess(keyId -> {
        LOGGER.info("Generated new key with ID: {}", keyId);
        
        // Step 2: Generate CSR using the new key
        metadataVaultHandler.generateIntermediateCsrWithKeyRef(
            NATS_PKI_MOUNT, 
            "NATS Intermediate Authority",
            keyName  // Use key name as reference
          )
          .onFailure(genErr -> {
            LOGGER.error("Failed to generate intermediate CSR", genErr);
            outerPromise.fail(genErr);
          })
          .onSuccess(csrWithKey -> {
            LOGGER.info("Generated intermediate CSR with key {}", keyId);

            // Step 3: Sign CSR with root
            metadataVaultHandler.signCsrWithRoot(VAULT_ROOT_CA_PATH, csrWithKey.getCsr(), 
                                                 caEpochUtil.buildCaTTLString())
              .onFailure(signErr -> {
                LOGGER.error("Failed to sign CSR with root", signErr);
                outerPromise.fail(signErr);
              })
              .onSuccess(signedCert -> {
                LOGGER.info("Received signed intermediate from root ({} chars)", 
                  signedCert != null ? signedCert.length() : 0);

                if (!isValidPemCertificate(signedCert))
                {
                  String msg = "Invalid PEM in signed certificate from root";
                  LOGGER.error(msg);
                  outerPromise.fail(msg);
                  return;
                }

                // Step 4: Import signed cert (associates with the key automatically)
                metadataVaultHandler.setIntermediateSignedCertificateInternal(NATS_PKI_MOUNT, signedCert)
                  .onFailure(setErr -> {
                    LOGGER.error("Failed to set signed intermediate on PKI mount", setErr);
                    outerPromise.fail(setErr);
                  })
                  .onSuccess(issuerId -> {
                    LOGGER.info("Set intermediate signed certificate, issuerId={}", issuerId);

                    // Set default issuer
                    Future<Void> setDefaultFuture;
                    if (issuerId != null && !issuerId.isEmpty())
                    {
                      LOGGER.info("Setting default issuer to: {}", issuerId);
                      setDefaultFuture = metadataVaultHandler.setDefaultIssuer(NATS_PKI_MOUNT, issuerId)
                        .recover(setDefaultErr -> {
                          LOGGER.warn("Unable to set default issuer (non-fatal): {}", setDefaultErr.getMessage());
                          return Future.succeededFuture((Void) null);
                        });
                    }
                    else
                    {
                      LOGGER.warn("⚠️  No issuer ID found - default issuer not set");
                      setDefaultFuture = Future.succeededFuture((Void) null);
                    }

                    setDefaultFuture
                      .compose(ignored -> waitForProcessing(1500))
                      .compose(v2 -> metadataVaultHandler.buildCompleteCABundleWithNew(existingSnapshot, signedCert))
                      .onSuccess(mergedBundle -> {
                        LOGGER.info("Built merged CA bundle ({} chars)", 
                          mergedBundle != null ? mergedBundle.length() : 0);
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
  }
   */
  
  /**
   * Build published bundle with existing certs
   */
  private Future<String> buildPublishedBundle(String newBundle)
  {
    return metadataVaultHandler.getCAChainEnhanced(VAULT_ROOT_CA_PATH)
      .recover(err -> {
        LOGGER.warn("Failed to get enhanced root CA chain, trying standard: {}", err.getMessage());
        return metadataVaultHandler.getCAChainEnhanced(VAULT_ROOT_CA_PATH);
      })
      .compose(rootBundle -> workerExecutor.executeBlocking(() -> {
        try
        {
          List<String> parts = new ArrayList<>();

          // Existing intermediates from local secret
          try
          {
            Secret existing = kubeClient.secrets().inNamespace(namespace)
              .withName(LOCAL_CA_SECRET_NAME).get();
            if (existing != null && existing.getData() != null && 
                existing.getData().containsKey(LOCAL_CA_SECRET_KEY))
            {
              String existingB64 = existing.getData().get(LOCAL_CA_SECRET_KEY);
              if (existingB64 != null && !existingB64.isBlank())
              {
                String existingPem = decodeSecretData(existingB64);
                if (existingPem != null && isValidPemBundle(existingPem))
                {
                  List<String> existingCerts = splitPemCertificates(existingPem);
                  parts.addAll(existingCerts);
                  LOGGER.info("Found {} certificate(s) in existing {} secret", 
                    existingCerts.size(), LOCAL_CA_SECRET_NAME);
                }
              }
            }
          }
          catch (Exception e)
          {
            LOGGER.warn("Error reading existing {} secret: {}", LOCAL_CA_SECRET_NAME, e.getMessage());
          }

          // New bundle
          if (newBundle != null && !newBundle.trim().isEmpty())
          {
            if (isValidPemBundle(newBundle))
            {
              List<String> newCerts = splitPemCertificates(newBundle);
              parts.addAll(newCerts);
              LOGGER.info("New bundle contains {} certificate(s)", newCerts.size());
            }
          }

          // Root bundle
          if (rootBundle != null && !rootBundle.trim().isEmpty())
          {
            if (isValidPemBundle(rootBundle))
            {
              List<String> rootCerts = splitPemCertificates(rootBundle);
              parts.addAll(rootCerts);
              LOGGER.info("Root bundle contains {} certificate(s)", rootCerts.size());
            }
          }

          // Deduplicate
          LinkedHashMap<String, String> unique = new LinkedHashMap<>();
          for (String certPem : parts)
          {
            String norm = certPem.replaceAll("\\r", "").trim();
            if (!norm.isEmpty() && !unique.containsKey(norm))
            {
              unique.put(norm, norm);
            }
          }

          StringBuilder merged = new StringBuilder();
          for (String pem : unique.values())
          {
            if (merged.length() > 0) merged.append("\n");
            merged.append(pem.trim());
          }

          String mergedPem = merged.toString();
          LOGGER.info("Built merged PEM bundle with {} certificate(s)", unique.size());
          return mergedPem;
        }
        catch (Exception e)
        {
          throw new RuntimeException("Failed to build published CA bundle: " + e.getMessage(), e);
        }
      }));
  }

  /**
   * Persist local CA bundle
   */
  private Future<Void> persistLocalCaBundle(String mergedBundle)
  {
    return workerExecutor.executeBlocking(() -> {
      if (!isValidPemBundle(mergedBundle))
      {
        throw new RuntimeException("Invalid PEM format - cannot persist local CA bundle");
      }

      updateLocalCaBundle(mergedBundle);
      LOGGER.info("Persisted local CA bundle successfully (metadata local secret updated)");
      return null;
    });
  }

  /**
   * Update local CA bundle secret
   */
  private void updateLocalCaBundle(String caBundle)
  {
    try
    {
      LOGGER.info("Updating local CA bundle secret {}/{}", namespace, LOCAL_CA_SECRET_NAME);

      if (!isValidPemBundle(caBundle))
      {
        LOGGER.error("Cannot update local CA bundle: invalid PEM format");
        throw new RuntimeException("Invalid PEM format in CA bundle");
      }

      Secret secret = kubeClient.secrets().inNamespace(namespace).withName(LOCAL_CA_SECRET_NAME).get();

      if (secret == null)
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
        catch (KubernetesClientException kce)
        {
          if (kce.getCode() == 403 || 
              (kce.getMessage() != null && kce.getMessage().toLowerCase().contains("forbidden")))
          {
            LOGGER.error("RBAC: insufficient permissions to create local secret '{}' in namespace '{}'. " +
              "Grant create/patch/update on secrets to the rotator ServiceAccount. Error: {}",
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
        Secret updated = new SecretBuilder()
          .withNewMetadata()
            .withName(LOCAL_CA_SECRET_NAME)
            .withNamespace(namespace)
          .endMetadata()
          .addToStringData(LOCAL_CA_SECRET_KEY, caBundle)
          .build();

        try
        {
          kubeClient.secrets().inNamespace(namespace).resource(updated).serverSideApply();
          LOGGER.info("Replaced existing local CA bundle secret {}/{}", namespace, LOCAL_CA_SECRET_NAME);
        }
        catch (KubernetesClientException kce)
        {
          if (kce.getCode() == 403 || 
              (kce.getMessage() != null && kce.getMessage().toLowerCase().contains("forbidden")))
          {
            LOGGER.error("RBAC: insufficient permissions to update local secret '{}' in namespace '{}'. " +
              "Grant update/patch on secrets to the rotator ServiceAccount. Error: {}",
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
    catch (Exception e)
    {
      LOGGER.error("Failed to update local CA bundle: {}", e.getMessage(), e);
      throw new RuntimeException("CA bundle update failed", e);
    }
  }

  /**
   * Decode secret data from base64
   */
  private String decodeSecretData(String encodedData)
  {
    try
    {
      byte[] decoded = Base64.getDecoder().decode(encodedData);
      String result = new String(decoded, StandardCharsets.UTF_8);
      
      if (isValidPemBundle(result))
      {
        return result;
      }
      else
      {
        LOGGER.warn("Decoded data is not valid PEM format");
        return null;
      }
    }
    catch (Exception e)
    {
      LOGGER.warn("Failed to decode secret data as Base64: {}", e.getMessage());
      
      if (isValidPemBundle(encodedData))
      {
        LOGGER.info("Data appears to already be in PEM format");
        return encodedData;
      }
      
      return null;
    }
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
    
    return PEM_CERT_PATTERN.matcher(pemData).find();
  }

  /**
   * Validate single PEM certificate
   */
  private boolean isValidPemCertificate(String pemData)
  {
    if (pemData == null || pemData.trim().isEmpty())
    {
      return false;
    }
    
    return PEM_CERT_PATTERN.matcher(pemData).find();
  }

  /**
   * Split PEM bundle into individual certificates
   */
  private List<String> splitPemCertificates(String pemBundle)
  {
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
   * Build CaBundle message
   */
  private Future<CaBundle> buildCaBundle(String serverId, String caBundle)
  {
    return workerExecutor.executeBlocking(() ->
    {
      Instant timestamp = Instant.now();
      String caVersion = timestamp.toString();
      long caEpochNum = caEpochUtil.epochNumberForInstant(timestamp);

      CaBundle bundle = new CaBundle(serverId, timestamp, caEpochNum, 
        ServiceCoreIF.CaRotationEvent, caBundle, caVersion);
      return bundle;
    });
  }

  /**
   * Enhanced CA rotation event publishing with retry
   */
  private Future<String> publishCARotationEventWithRetry(String serverId, String caBundle, int attemptCount)
  {
    if (attemptCount >= MAX_ROTATION_RETRIES)
    {
      return Future.failedFuture("Maximum publish attempts exceeded");
    }

    return generateSignedMessage(serverId, caBundle)
      .compose(signedMsg ->
      {
        try
        {
          byte[] signedBytes = SignedMessage.serialize(signedMsg);
          if (signedBytes == null || signedBytes.length == 0)
          {
            return Future.failedFuture("Failed to serialize SignedMessage for CA bundle");
          }

          return natsTLSClient.publish(ServiceCoreIF.MetaDataClientCaCertStream, signedBytes)
            .compose(v -> {
              LOGGER.info("Published SignedMessage for CA rotation event to NATS subject: {}", 
                ServiceCoreIF.MetaDataClientCaCertStream);
              return Future.succeededFuture("success");
            });
        }
        catch (Exception e)
        {
          String errMsg = "Error publishing CaBundle. Error = " + e.getMessage();
          LOGGER.error(errMsg, e);
          return Future.failedFuture(errMsg);
        }
      })
      .recover(err -> {
        LOGGER.warn("Failed to publish CA rotation event (attempt {}): {}", attemptCount + 1, err.getMessage());
        
        if (attemptCount < MAX_ROTATION_RETRIES - 1)
        {
          long retryDelayMs = 5000 * (attemptCount + 1);
          
          Promise<String> retryPromise = Promise.promise();
          vertx.setTimer(retryDelayMs, id -> {
            LOGGER.info("Retrying CA rotation event publish (attempt {})", attemptCount + 2);
            publishCARotationEventWithRetry(serverId, caBundle, attemptCount + 1)
              .onComplete(retryPromise);
          });
          
          return retryPromise.future();
        }
        else
        {
          return Future.failedFuture("Failed to publish CA rotation event after " + 
            MAX_ROTATION_RETRIES + " attempts");
        }
      });
  }

  /**
   * Generate SignedMessage for CA bundle
   */
  private Future<SignedMessage> generateSignedMessage(String serverId, String caBundle)
  {
    LOGGER.info("Generating CA Bundle SignedMessage for server: {}", serverId);

    return buildCaBundle(serverId, caBundle)
      .compose(bundle ->
        workerExecutor.executeBlocking(() ->
        {
          byte[] serializedBundle = CaBundle.serialize(bundle);
          if (serializedBundle == null || serializedBundle.length == 0)
          {
            throw new RuntimeException("Failed to serialize CaBundle for server: " + serverId);
          }
          return serializedBundle;
        })
      )
      .compose(serializedBundle ->
        getMetadataSigningKey()
          .compose(signKey ->
            signer.sign(serializedBundle, signKey)
              .compose(signature ->
                workerExecutor.executeBlocking(() ->
                {
                  long keyEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
                  List<TopicKey> keyList = keyCache.getValidTopicKeysSorted(
                    ServiceCoreIF.MetaDataClientCaCertStream);
                  TopicKey topicKey = null;

                  for (TopicKey key : keyList)
                  {
                    if (keyEpoch == key.getEpochNumber())
                    {
                      topicKey = key;
                      break;
                    }
                  }

                  if (topicKey == null)
                  {
                    String errMsg = "Generating SignedMessage process could not obtain an encryption key.";
                    LOGGER.error(errMsg);
                    throw new RuntimeException(errMsg);
                  }

                  EncryptedData encData = aesCrypto.encrypt(serializedBundle, topicKey.getKeyData());
                  if (encData == null || encData.getCiphertext() == null || encData.getCiphertext().length == 0)
                  {
                    throw new RuntimeException("Failed to encrypt CaBundle for server: " + serverId);
                  }

                  LOGGER.info("Successfully generated and encrypted CaBundle for server: {}", serverId);

                  Instant now = Instant.now();
                  long caEpoch = caEpochUtil.epochNumberForInstant(now);

                  return new SignedMessage(serverId + now.toString(),
                    "CaBundle",
                    caEpoch,
                    keyEpoch,
                    "metadata",
                    signKey.getEpochNumber(),
                    now,
                    signature,
                    ServiceCoreIF.MetaDataClientCaCertStream,
                    topicKey.getKeyId(),
                    "CaBundle",
                    encData.serialize());
                })
              )
          )
      )
      .onFailure(err ->
      {
        LOGGER.error("Failed to process CA Bundle for server: {}", serverId, err);
      });
  }

  /**
   * Get metadata signing key from event bus
   */
  public Future<DilithiumKey> getMetadataSigningKey()
  {
    return vertx.eventBus().<Buffer>request(ServicesACLWatcherVert.METADATA__SIGNING_KEY_ADDR, "metadata")
      .compose(msg ->
      {
        try
        {
          DilithiumKey key = DilithiumKey.deSerialize(msg.body().getBytes(), "transport");
          return Future.succeededFuture(key);
        }
        catch (Exception e)
        {
          return Future.failedFuture(e);
        }
      });
  }

  /**
   * Wait for processing delay
   */
  private Future<Void> waitForProcessing(long delayMs)
  {
    Promise<Void> p = Promise.promise();
    vertx.setTimer(delayMs, id -> p.complete());
    return p.future();
  }
}