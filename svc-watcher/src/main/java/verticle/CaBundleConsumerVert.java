package verticle;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.KeySecretManager;
import core.model.CaBundle;
import core.processor.SignedMessageProcessor;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.nats.client.JetStreamSubscription;
import io.nats.client.Message;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;

import core.nats.NatsTLSClient;
import processor.NatsCaBundleMsgProcessor;
import utils.WatcherConfig;

/**
 * CA Bundle Consumer Verticle - Async Pull Consumer Implementation
 * 
 * Fetches CA bundle rotation messages from METADATA_CA_CLIENT stream.
 * Uses single-flight rotation with epoch coalescing to prevent concurrent rotations.
 * 
 * Updated to use per-service consumer naming for consistency with other services.
 * 
 * @author t-snyder
 * @date 2025-01-04
 * @version 2.0
 */
public class CaBundleConsumerVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger(CaBundleConsumerVert.class);
  
  // FIXED: Changed stream name to match deployment script
  private static final String STREAM_NAME = "METADATA_CA_CLIENT";
  private static final String SERVICE_ID = "watcher";
  private static final int BATCH_SIZE = 1; // CA updates are infrequent
  private static final long FETCH_TIMEOUT_MS = 1000;
  private static final long PULL_INTERVAL_MS = 500;

  private final KubernetesClient kubeClient;
  private final WatcherConfig config;
  private final NatsTLSClient natsTlsClient;
  private final KeySecretManager keyCache;
  private final String namespace;

  private WorkerExecutor workerExecutor;
  private JetStreamSubscription caSubscription;

  private NatsCaBundleMsgProcessor rotationProcessor;
  private SignedMessageProcessor epochExtractor;

  // Rotation coordination
  private final AtomicBoolean rotationInProgress = new AtomicBoolean(false);
  private volatile long currentEpoch = -1L;
  private final AtomicReference<Pending> pending = new AtomicReference<>(null);

  private static final class Pending
  {
    final long epoch;
    final byte[] raw;

    Pending(long epoch, byte[] raw)
    {
      this.epoch = epoch;
      this.raw = raw;
    }
  }

  public CaBundleConsumerVert(KubernetesClient kubeClient, NatsTLSClient natsTlsClient, 
                              KeySecretManager keyCache, WatcherConfig config, String namespace)
  {
    this.kubeClient = kubeClient;
    this.natsTlsClient = natsTlsClient;
    this.keyCache = keyCache;
    this.config = config;
    this.namespace = namespace;
  }

  @Override
  public void start(Promise<Void> startPromise)
  {
    LOGGER.info("╔═══════════════════════════════════════════════════════════════════╗");
    LOGGER.info("║ CaBundleConsumerVert initializing                                 ║");
    LOGGER.info("║ Service: {}                                              ║", String.format("%-44s", SERVICE_ID));
    LOGGER.info("║ Stream: {}                                       ║", String.format("%-45s", STREAM_NAME));
    LOGGER.info("║ Consumer: {}-ca-consumer                                  ║", String.format("%-34s", SERVICE_ID));
    LOGGER.info("╚═══════════════════════════════════════════════════════════════════╝");
    
    try
    {
      workerExecutor = vertx.createSharedWorkerExecutor("ca-msg-handler", 8);
      rotationProcessor = new NatsCaBundleMsgProcessor(vertx, workerExecutor, kubeClient, 
                                                       natsTlsClient, keyCache);
      epochExtractor = new SignedMessageProcessor(workerExecutor, keyCache);

      startCAConsumer()
        .onSuccess(v -> 
        {
          LOGGER.info("✅ CaBundleConsumerVert started successfully with async pull consumer");
          startPromise.complete();
        })
        .onFailure(e -> 
        {
          LOGGER.error("❌ Failed to start CaBundleConsumerVert: {}", e.getMessage(), e);
          cleanup();
          startPromise.fail(e);
        });
    }
    catch (Exception e)
    {
      LOGGER.error("❌ Exception during CaBundleConsumerVert initialization: {}", e.getMessage(), e);
      startPromise.fail(e);
    }
  }

  /**
   * Bind to async pull consumer for CA bundle updates
   * UPDATED: Now uses per-service consumer name (watcher-ca-consumer)
   */
  private Future<Void> startCAConsumer()
  {
    // FIXED: Changed from "metadata-client-ca-cert" to per-service naming
    String durableName = SERVICE_ID + "-ca-consumer";  // = "watcher-ca-consumer"
    
    LOGGER.info("🔗 Binding to CA Bundle async pull consumer");
    LOGGER.info("   Stream: {}", STREAM_NAME);
    LOGGER.info("   Durable: {}", durableName);
    LOGGER.info("   Service: {}", SERVICE_ID);

    Promise<Void> promise = Promise.promise();

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
      LOGGER.info("║ Service: {}                                              ║", String.format("%-44s", SERVICE_ID));
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
      cleanup();
      promise.fail(err);
    });

    return promise.future();
  }

  /**
   * Handle CA bundle message - ASYNC VERSION
   * Returns Future that completes when epoch extraction and scheduling is done
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
      extractEpoch(msgBytes)
        .onComplete(ar -> {
          if (ar.failed())
          {
            LOGGER.error("❌ Epoch extraction failed: {}", ar.cause().getMessage(), ar.cause());
            promise.fail(ar.cause());
            return;
          }
          
          long epoch = ar.result();
          
          if (epoch < 0)
          {
            LOGGER.warn("⚠️  Invalid CA bundle epoch ({}); ignoring", epoch);
            promise.complete(); // Complete successfully to ack invalid message
            return;
          }

          LOGGER.info("📊 CA bundle epoch: {}", epoch);

          // Schedule or queue rotation (non-blocking)
          scheduleOrQueue(epoch, msgBytes);
          
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
   * Schedule or queue rotation based on epoch
   */
  private void scheduleOrQueue(long epoch, byte[] raw)
  {
    long cur = currentEpoch;
    
    if (epoch <= cur)
    {
      LOGGER.info("⏭️  Ignoring stale CA bundle epoch={} (currentEpoch={})", epoch, cur);
      return;
    }

    if (rotationInProgress.compareAndSet(false, true))
    {
      currentEpoch = epoch;
      LOGGER.info("╔═══════════════════════════════════════════════════════════════════╗");
      LOGGER.info("║ 🔄 STARTING CA BUNDLE ROTATION                                    ║");
      LOGGER.info("║ Epoch: {}                                                    ║", String.format("%-50s", epoch));
      LOGGER.info("║ Status: No active rotation                                        ║");
      LOGGER.info("╚═══════════════════════════════════════════════════════════════════╝");
      startRotation(epoch, raw);
    }
    else
    {
      Pending prev = pending.get();
      while (true)
      {
        if (prev == null)
        {
          if (pending.compareAndSet(null, new Pending(epoch, raw)))
          {
            LOGGER.info("📥 Queued CA bundle rotation epoch={} (active rotation currentEpoch={})", 
                       epoch, currentEpoch);
            break;
          }
        }
        else if (epoch > prev.epoch)
        {
          if (pending.compareAndSet(prev, new Pending(epoch, raw)))
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
        prev = pending.get();
      }
    }
  }

  /**
   * Start CA rotation process
   */
  private void startRotation(long epoch, byte[] raw)
  {
    long startTime = System.currentTimeMillis();
    
    rotationProcessor.processMsg(raw).onComplete(ar -> 
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
        LOGGER.info("╚═══════════════════════════════════════════════════════════════════╝");
      }
      
      // Check for pending rotation
      Pending next = pending.getAndSet(null);
      if (next != null && next.epoch > currentEpoch)
      {
        LOGGER.info("🔄 Promoting queued rotation epoch={} (previous epoch={})", 
                   next.epoch, currentEpoch);
        currentEpoch = next.epoch;
        startRotation(next.epoch, next.raw);
        return;
      }
      
      rotationInProgress.set(false);
      LOGGER.info("Rotation cycle ended epoch={} (no newer pending)", epoch);
    });
  }

  /**
   * Extract epoch from signed message (async)
   */
  private Future<Long> extractEpoch(byte[] signedBytes)
  {
    return epochExtractor.obtainDomainObject(signedBytes)
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

  @Override
  public void stop(Promise<Void> stopPromise)
  {
    LOGGER.info("Stopping CaBundleConsumerVert for service: {}", SERVICE_ID);
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
          LOGGER.warn("⚠️  Error unsubscribing: {}", e.getMessage());
        }
        caSubscription = null;
      }
      
      if (workerExecutor != null)
      {
        try
        {
          LOGGER.info("Closing worker executor...");
          workerExecutor.close();
          LOGGER.info("✅ Worker executor closed");
        }
        catch (Exception e)
        {
          LOGGER.warn("⚠️  Error closing worker executor: {}", e.getMessage());
        }
        workerExecutor = null;
      }
      
      LOGGER.info("✅ CaBundleConsumerVert cleanup completed for service: {}", SERVICE_ID);
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