package core.verticle;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import io.nats.client.Connection;
import io.nats.client.JetStreamManagement;
import io.nats.client.JetStreamSubscription;
import io.nats.client.Message;
import io.nats.client.api.ConsumerInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.CaSecretManager;
import core.handler.KeySecretManager;
import core.model.CaBundle;
import core.nats.NatsTLSClient;
import core.processor.SignedMessageProcessor;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;

/**
 * CA Bundle Update Verticle for Client Services - Async Pull Consumer Implementation
 * 
 * Fetches CA bundle updates from service-specific pull consumer.
 * Handles CA rotation with single-flight protection and epoch coalescing.
 * 
 * Key fixes in this version:
 * - Corrected stream name from METADATA_CLIENT to METADATA_CA_CLIENT
 * - Added retry logic with exponential backoff for consumer binding
 * - Enhanced diagnostic logging
 * - Added stream/consumer existence verification before binding
 * 
 * @author t-snyder
 * @date 2025-01-04
 * @version 2.0
 */
public class CABundleUpdateVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger(CABundleUpdateVert.class);

  // FIXED: Changed from "METADATA_CLIENT" to "METADATA_CA_CLIENT" to match deployment script
  private static final String STREAM_NAME = "METADATA_CA_CLIENT";
  private static final int BATCH_SIZE = 1;
  private static final long FETCH_TIMEOUT_MS = 1000;
  private static final long PULL_INTERVAL_MS = 500;
  
  // Retry configuration
  private static final int MAX_BIND_RETRIES = 5;
  private static final long INITIAL_RETRY_DELAY_MS = 2000;
  private static final double RETRY_BACKOFF_MULTIPLIER = 2.0;

  private final NatsTLSClient natsTlsClient;
  private final KeySecretManager keyCache;
  private CaSecretManager caSecretManager;
  private WorkerExecutor workerExecutor;
  private JetStreamSubscription caSubscription;
  private SignedMessageProcessor signedMsgProcessor;
  private final KubernetesClient kubeClient;
  private final String serviceId;
  private final String namespace;

  // Rotation coordination
  private final AtomicBoolean rotationInProgress = new AtomicBoolean(false);
  private volatile long currentEpoch = -1L;
  private final AtomicReference<PendingRotation> pendingRotation = new AtomicReference<>(null);

  private static final class PendingRotation
  {
    final long epoch;
    final byte[] messageBytes;

    PendingRotation(long epoch, byte[] messageBytes)
    {
      this.epoch = epoch;
      this.messageBytes = messageBytes;
    }
  }

  public CABundleUpdateVert(KubernetesClient kubeClient, NatsTLSClient natsTlsClient,
                           KeySecretManager keyCache, String serviceId, String namespace)
  {
    this.kubeClient = kubeClient;
    this.natsTlsClient = natsTlsClient;
    this.keyCache = keyCache;
    this.serviceId = serviceId;
    this.namespace = namespace;
  }

  @Override
  public void start(Promise<Void> startPromise)
  {
    this.workerExecutor = vertx.createSharedWorkerExecutor("ca-handler-" + serviceId, 8);
    this.signedMsgProcessor = new SignedMessageProcessor(workerExecutor, keyCache);
    this.caSecretManager = new CaSecretManager(kubeClient, namespace, serviceId);

    LOGGER.info("═══════════════════════════════════════════════════════════════════");
    LOGGER.info("CABundleUpdateVert initializing for Service: {}, Stream: {}, Consumer: {}-ca-consumer", serviceId, STREAM_NAME, serviceId);
    LOGGER.info("═══════════════════════════════════════════════════════════════════");

    startCAConsumerWithRetry(0, INITIAL_RETRY_DELAY_MS)
      .onSuccess(v -> 
      {
        LOGGER.info("✅ CABundleUpdateVert started successfully with async pull consumer");
        startPromise.complete();
      })
      .onFailure(e -> 
      {
        LOGGER.error("❌ Failed to start CABundleUpdateVert after {} retries: {}", 
                    MAX_BIND_RETRIES, e.getMessage(), e);
        cleanup();
        startPromise.fail(e);
      });
  }

  /**
   * Start CA consumer with retry logic and exponential backoff
   */
  private Future<Void> startCAConsumerWithRetry(int attemptNumber, long delayMs)
  {
    if (attemptNumber >= MAX_BIND_RETRIES)
    {
      return Future.failedFuture(new RuntimeException(
        "Failed to bind CA consumer after " + MAX_BIND_RETRIES + " attempts"));
    }

    if (attemptNumber > 0)
    {
      LOGGER.info("⏳ Retry attempt {}/{} for CA consumer binding (delay: {}ms)", 
                 attemptNumber + 1, MAX_BIND_RETRIES, delayMs);
      
      Promise<Void> delayPromise = Promise.promise();
      vertx.setTimer(delayMs, id -> delayPromise.complete());
      
      return delayPromise.future()
        .compose(v -> startCAConsumer())
        .recover(err -> {
          long nextDelay = (long)(delayMs * RETRY_BACKOFF_MULTIPLIER);
          LOGGER.warn("Retry {}/{} failed: {} - retrying in {}ms", 
                     attemptNumber + 1, MAX_BIND_RETRIES, err.getMessage(), nextDelay);
          return startCAConsumerWithRetry(attemptNumber + 1, nextDelay);
        });
    }
    
    return startCAConsumer()
      .recover(err -> {
        LOGGER.warn("Initial bind attempt failed: {} - starting retry sequence", err.getMessage());
        return startCAConsumerWithRetry(attemptNumber + 1, delayMs);
      });
  }

  /**
   * Bind to service-specific CA bundle async pull consumer
   */
  private Future<Void> startCAConsumer()
  {
    String durableName = serviceId + "-ca-consumer";
    
    LOGGER.info("🔗 Binding to CA Bundle async pull consumer");
    LOGGER.info("   Stream: {}", STREAM_NAME);
    LOGGER.info("   Durable: {}", durableName);
    LOGGER.info("   Service: {}", serviceId);

    Promise<Void> promise = Promise.promise();

    // First, verify stream and consumer exist (diagnostic check)
    verifyStreamAndConsumer(STREAM_NAME, durableName)
      .onComplete(verifyResult -> {
        if (verifyResult.failed())
        {
          LOGGER.error("❌ Pre-bind verification failed: {}", verifyResult.cause().getMessage());
          // Don't fail immediately - let the actual bind attempt provide the definitive error
          LOGGER.warn("⚠️  Proceeding with bind attempt despite verification failure");
        }
        else
        {
          LOGGER.info("✅ Pre-bind verification passed: stream and consumer exist");
        }

        // Proceed with actual binding
        natsTlsClient.getConsumerPoolManager().bindPullConsumerAsync(
          STREAM_NAME,
          durableName,
          this::handleCAMessageAsync,  // ASYNC handler - returns Future<Void>
          BATCH_SIZE,
          FETCH_TIMEOUT_MS,
          PULL_INTERVAL_MS
        )
        .onSuccess(sub -> 
        {
          this.caSubscription = sub;
          LOGGER.info("╔═══════════════════════════════════════════════════════════════════╗");
          LOGGER.info("║ ✅ BOUND TO CA BUNDLE CONSUMER                                    ║");
          LOGGER.info("║ Service: {}                                              ║", String.format("%-44s", serviceId));
          LOGGER.info("║ Durable: {}                                      ║", String.format("%-44s", durableName));
          LOGGER.info("║ Stream: {}                                       ║", String.format("%-45s", STREAM_NAME));
          LOGGER.info("╚═══════════════════════════════════════════════════════════════════╝");
          promise.complete();
        })
        .onFailure(err -> 
        {
          LOGGER.error("╔═══════════════════════════════════════════════════════════════════╗");
          LOGGER.error("║ ❌ FAILED TO BIND CA CONSUMER                                     ║");
          LOGGER.error("║ Stream: {}                                       ║", String.format("%-45s", STREAM_NAME));
          LOGGER.error("║ Durable: {}                                      ║", String.format("%-44s", durableName));
          LOGGER.error("║ Error: {}║", String.format("%-47s", truncate(err.getMessage(), 47)));
          LOGGER.error("╚═══════════════════════════════════════════════════════════════════╝");
          promise.fail(err);
        });
      });

    return promise.future();
  }

  /**
   * Verify stream and consumer exist on NATS server (diagnostic check)
   */
  private Future<Void> verifyStreamAndConsumer(String streamName, String consumerName)
  {
    return workerExecutor.<Void>executeBlocking(() -> 
    {
      try
      {
        Connection conn = natsTlsClient.getNatsConnection();
        if (conn == null)
        {
          throw new IllegalStateException("No NATS connection available");
        }

        // Get JetStreamManagement from connection
        JetStreamManagement jsm = conn.jetStreamManagement();
        
        // Try to get consumer info - this will throw if stream or consumer doesn't exist
        ConsumerInfo consumerInfo = jsm.getConsumerInfo(streamName, consumerName);
        
        if (consumerInfo == null)
        {
          throw new IllegalStateException("Consumer info returned null for: " + consumerName);
        }
        
        LOGGER.info("📊 Consumer verification successful:");
        LOGGER.info("   Stream: {}", consumerInfo.getStreamName());
        LOGGER.info("   Consumer: {}", consumerInfo.getName());
        LOGGER.info("   Pending messages: {}", consumerInfo.getNumPending());
        LOGGER.info("   Ack pending: {}", consumerInfo.getNumAckPending());
        
        return null;
      }
      catch (Exception e)
      {
        String msg = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
        
        // Check for specific "not found" errors
        boolean notFound = msg.contains("consumer not found") ||
                          msg.contains("stream not found") ||
                          msg.contains("10014") ||  // Consumer not found error code
                          msg.contains("10059");    // Stream not found error code
        
        if (notFound)
        {
          LOGGER.warn("⚠️  Stream/Consumer not found: {} - this may be expected during initial deployment", e.getMessage());
        }
        else
        {
          LOGGER.warn("⚠️  Consumer verification failed: {}", e.getMessage());
        }
        
        throw new RuntimeException("Consumer verification failed: " + e.getMessage(), e);
      }
    });
  }

  /**
   * Handle CA bundle message - ASYNC VERSION
   * Returns Future that completes when processing is done
   */
  private Future<Void> handleCAMessageAsync(Message msg)
  {
    Promise<Void> promise = Promise.promise();
    
    try
    {
      byte[] msgBytes = msg.getData();
      
      if (msgBytes == null || msgBytes.length == 0)
      {
        LOGGER.warn("⚠️  Received empty CA bundle message; ignoring");
        promise.complete();
        return promise.future();
      }

      LOGGER.info("📨 Received CA bundle message ({} bytes)", msgBytes.length);

      // Extract epoch asynchronously
      extractEpochAsync(msgBytes)
        .onComplete(ar -> {
          if (ar.failed())
          {
            LOGGER.error("❌ Failed to extract epoch: {}", ar.cause().getMessage(), ar.cause());
            promise.fail(ar.cause());
            return;
          }
          
          long epoch = ar.result();
          
          if (epoch < 0)
          {
            LOGGER.warn("⚠️  Invalid CA bundle epoch ({}); ignoring message", epoch);
            promise.complete(); // Complete successfully to ack the invalid message
            return;
          }

          LOGGER.info("📊 CA bundle epoch: {}", epoch);

          // Schedule or queue rotation (non-blocking)
          scheduleOrQueueRotation(epoch, msgBytes);
          
          // Complete immediately - rotation happens asynchronously
          promise.complete();
        });
    }
    catch (Exception e)
    {
      LOGGER.error("❌ Exception in handleCAMessageAsync: {}", e.getMessage(), e);
      promise.fail(e);
    }
    
    return promise.future();
  }

  /**
   * Async epoch extraction
   */
  private Future<Long> extractEpochAsync(byte[] signedBytes)
  {
    return signedMsgProcessor.obtainDomainObject(signedBytes)
      .compose(payload -> workerExecutor.<Long>executeBlocking(() -> 
      {
        try
        {
          CaBundle ca = CaBundle.deSerialize(payload);
          if (ca == null)
          {
            LOGGER.error("❌ CaBundle deserialization returned null");
            return -1L;
          }
          
          long epoch = ca.getCaEpochNumber();
          LOGGER.debug("Extracted CA epoch: {}", epoch);
          return epoch;
        }
        catch (Exception e)
        {
          LOGGER.error("❌ Failed to deserialize CaBundle: {}", e.getMessage(), e);
          return -1L;
        }
      }));
  }

  /**
   * Schedule or queue CA rotation
   */
  private void scheduleOrQueueRotation(long epoch, byte[] msgBytes)
  {
    long currentEpochSnapshot = currentEpoch;

    if (epoch <= currentEpochSnapshot)
    {
      LOGGER.info("⏭️  Ignoring stale CA bundle epoch={} (currentEpoch={})", 
                 epoch, currentEpochSnapshot);
      return;
    }

    if (rotationInProgress.compareAndSet(false, true))
    {
      currentEpoch = epoch;
      LOGGER.info("═══════════════════════════════════════════════════════════════════");
      LOGGER.info(" 🔄 STARTING CA BUNDLE ROTATION - Epoch: {}", epoch);
      LOGGER.info(" Status: No active rotation");
      LOGGER.info("═══════════════════════════════════════════════════════════════════");
      startRotation(epoch, msgBytes);
    }
    else
    {
      PendingRotation prev = pendingRotation.get();
      while (true)
      {
        if (prev == null)
        {
          if (pendingRotation.compareAndSet(null, new PendingRotation(epoch, msgBytes)))
          {
            LOGGER.info("📥 Queued CA bundle rotation epoch={} (active rotation currentEpoch={})",
                       epoch, currentEpochSnapshot);
            break;
          }
        }
        else if (epoch > prev.epoch)
        {
          if (pendingRotation.compareAndSet(prev, new PendingRotation(epoch, msgBytes)))
          {
            LOGGER.info("🔄 Replaced queued rotation epoch={} with newer epoch={}", 
                       prev.epoch, epoch);
            break;
          }
        }
        else
        {
          LOGGER.info("⏭️  Discarding incoming epoch={} (<= queuedEpoch={}) while rotation active",
                     epoch, prev.epoch);
          break;
        }
        prev = pendingRotation.get();
      }
    }
  }

  /**
   * Start CA rotation process
   */
  private void startRotation(long epoch, byte[] msgBytes)
  {
    long startTime = System.currentTimeMillis();

    handleBundleMsg(msgBytes).onComplete(ar -> 
    {
      long elapsed = System.currentTimeMillis() - startTime;

      if (ar.failed())
      {
        LOGGER.error("╔═══════════════════════════════════════════════════════════════════╗");
        LOGGER.error("║ ❌ CA BUNDLE ROTATION FAILED                                      ║");
        LOGGER.error("║ Epoch: {}                                                    ║", String.format("%-50s", epoch));
        LOGGER.error("║ Duration: {}ms                                              ║", String.format("%-45s", elapsed));
        LOGGER.error("║ Error: {}║", String.format("%-47s", truncate(ar.cause().getMessage(), 47)));
        LOGGER.error("╚═══════════════════════════════════════════════════════════════════╝", ar.cause());
      }
      else
      {
        LOGGER.info("╔═══════════════════════════════════════════════════════════════════╗");
        LOGGER.info("║ ✅ CA ROTATION COMPLETE                                           ║");
        LOGGER.info("║ Epoch: {}                                                    ║", String.format("%-50s", epoch));
        LOGGER.info("║ Duration: {}ms                                              ║", String.format("%-45s", elapsed));
        LOGGER.info("║ New connection active, all pools recreated                        ║");
        LOGGER.info("╚═══════════════════════════════════════════════════════════════════╝");
      }

      // Check for pending rotation
      PendingRotation next = pendingRotation.getAndSet(null);
      if (next != null && next.epoch > currentEpoch)
      {
        LOGGER.info("🔄 Promoting queued rotation epoch={} (previous epoch={})", 
                   next.epoch, currentEpoch);
        currentEpoch = next.epoch;
        startRotation(next.epoch, next.messageBytes);
        return;
      }

      rotationInProgress.set(false);
    });
  }

  /**
   * Handle CA bundle message - decrypt, verify, apply
   */
  private Future<Void> handleBundleMsg(byte[] signedMsgBytes)
  {
    LOGGER.info("═══════════════════════════════════════════════════════════════════");
    LOGGER.info("CLIENT SERVICE: Processing CA bundle message");
    LOGGER.info("Service: {}", serviceId);
    LOGGER.info("═══════════════════════════════════════════════════════════════════");

    return signedMsgProcessor.obtainDomainObject(signedMsgBytes)
      .compose(requestBytes -> workerExecutor.<CaBundle>executeBlocking(() -> 
      {
        try
        {
          CaBundle bundle = CaBundle.deSerialize(requestBytes);
          if (bundle == null)
          {
            throw new RuntimeException("CaBundle deserialization returned null");
          }
          return bundle;
        }
        catch (Exception e)
        {
          LOGGER.error("❌ Error deserializing CaBundle: {}", e.getMessage(), e);
          throw new RuntimeException("Failed to deserialize CaBundle", e);
        }
      }))
      .compose(caBundle -> 
      {
        LOGGER.info("✅ Successfully decrypted and verified caBundle");
        LOGGER.info("   Server: {}", caBundle.getServerId());
        LOGGER.info("   Epoch: {}", caBundle.getCaEpochNumber());

        // Step 1: Update Kubernetes secret
        return workerExecutor.<Void>executeBlocking(() -> 
        {
          try
          {
            caSecretManager.updateCaSecret(caBundle);
            LOGGER.info("✅ Step 1/2: CA secret updated in Kubernetes");
            return null;
          }
          catch (Exception e)
          {
            LOGGER.error("❌ Failed to update CA secret: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to update CA secret", e);
          }
        })
        .compose(v -> 
        {
          // Step 2: Proactive connection recreation
          LOGGER.info("🔄 Step 2/2: Calling NatsTLSClient.handleCaBundleUpdate()");
          LOGGER.info("   → Writes new CA file");
          LOGGER.info("   → Creates new NATS connection with new SSLContext");
          LOGGER.info("   → Recreates all producer/consumer pools");
          LOGGER.info("   → Closes old connection");
          
          return natsTlsClient.handleCaBundleUpdate(caBundle);
        })
        .compose(v -> 
        {
          LOGGER.info("✅ Step 2/2: CA rotation complete!");
          LOGGER.info("   → New connection active");
          LOGGER.info("   → All pools recreated");
          LOGGER.info("   → Old connection closed");
          return Future.succeededFuture();
        });
      });
  }

  @Override
  public void stop(Promise<Void> stopPromise)
  {
    LOGGER.info("Stopping CABundleUpdateVert for service: {}", serviceId);
    cleanup();
    stopPromise.complete();
  }

  private void cleanup()
  {
    try
    {
      if (caSubscription != null)
      {
        try
        {
          LOGGER.info("Draining CA subscription...");
          caSubscription.drain(Duration.ofSeconds(2));
          caSubscription.unsubscribe();
          LOGGER.info("✅ CA subscription closed");
        }
        catch (Exception e)
        {
          LOGGER.warn("⚠️  Error closing subscription: {}", e.getMessage());
        }
        caSubscription = null;
      }

      if (workerExecutor != null)
      {
        LOGGER.info("Closing worker executor...");
        workerExecutor.close();
        LOGGER.info("✅ Worker executor closed");
      }

      if (caSecretManager != null)
      {
        LOGGER.info("Closing CA secret manager...");
        caSecretManager.close();
        LOGGER.info("✅ CA secret manager closed");
      }

      LOGGER.info("✅ CABundleUpdateVert cleaned up for service: {}", serviceId);
    }
    catch (Exception e)
    {
      LOGGER.error("❌ Error during cleanup: {}", e.getMessage(), e);
    }
  }

  /**
   * Truncate string to fit in log message boxes
   */
  private String truncate(String str, int maxLength)
  {
    if (str == null)
      return "null";
    if (str.length() <= maxLength)
      return str;
    return str.substring(0, maxLength - 3) + "...";
  }
}