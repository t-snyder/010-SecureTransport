package core.verticle;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import io.nats.client.JetStreamSubscription;
import io.nats.client.Message;
import io.nats.client.MessageHandler;
import io.nats.client.Subscription;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.CaSecretManager;
import core.handler.KeySecretManager;
import core.model.CaBundle;
import core.model.ServiceCoreIF;
import core.processor.SignedMessageProcessor;
//import core.nats.NatsConsumerErrorHandler;
import core.nats.NatsTLSClient;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;

/**
 * CA Bundle Update Verticle for Client Services
 */
public class CABundleUpdateVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger(CABundleUpdateVert.class);

//  private final NatsConsumerErrorHandler errHandler = new NatsConsumerErrorHandler();
  private final NatsTLSClient natsTlsClient;
  private final KeySecretManager keyCache;
  private CaSecretManager caSecretManager;
  private WorkerExecutor workerExecutor;
  // changed to Subscription to accept both JetStreamSubscription and plain NATS Subscription
  private Subscription caSubscription;
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

    LOGGER.info("CABundleUpdateVert initializing for service: {}", serviceId);

    startCAConsumer()
      .onSuccess(v -> {
        LOGGER.info("CABundleUpdateVert started successfully");
        startPromise.complete();
      })
      .onFailure(e -> {
        LOGGER.error("Error starting CABundleUpdateVert: {}", e.getMessage(), e);
        cleanup();
        startPromise.fail(e);
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
          // drain only if JetStreamSubscription
          if (caSubscription instanceof JetStreamSubscription)
          {
            try { ((JetStreamSubscription) caSubscription).drain(Duration.ofSeconds(2)); } catch (Exception ignore) {}
          }
        }
        catch (Throwable ignored) {}

        try
        {
          caSubscription.unsubscribe();
        }
        catch (Exception ignore) {}
        caSubscription = null;
      }

      if (workerExecutor != null)
      {
        workerExecutor.close();
      }

      if (caSecretManager != null)
      {
        caSecretManager.close();
      }

      LOGGER.info("CABundleUpdateVert cleaned up for service: {}", serviceId);
    }
    catch (Exception e)
    {
      LOGGER.error("Error during cleanup: {}", e.getMessage(), e);
    }
  }

  private Future<Void> startCAConsumer()
  {
    LOGGER.info("Starting CA Bundle JetStream consumer");

    MessageHandler handler = createCAMessageHandler();

    // Attach to admin-created push consumer queue (use the queue group name created by bootstrap)
    String queueGroup = "metadata-client-ca"; // must match the admin-created deliverGroup
    return natsTlsClient.attachPushQueue(ServiceCoreIF.MetaDataClientCaCertStream, queueGroup, handler)
      .compose(sub -> 
      {
        this.caSubscription = sub; // no cast
        if (sub instanceof JetStreamSubscription)
        {
          LOGGER.info("CA Bundle consumer attached as JetStreamSubscription to subject {} queue {}", ServiceCoreIF.MetaDataClientCaCertStream, queueGroup);
        }
        else
        {
          LOGGER.info("CA Bundle consumer attached as plain NATS Subscription to subject {} queue {}", ServiceCoreIF.MetaDataClientCaCertStream, queueGroup);
        }
        return Future.succeededFuture((Void) null);
      })
      .onFailure(err -> LOGGER.error("Failed to attach CA consumer: {}", err.getMessage(), err));
  }

  private MessageHandler createCAMessageHandler()
  {
    return (Message msg) -> {
      byte[] msgBytes = msg.getData();

      extractEpoch(msgBytes).onComplete(ar -> {
        if (ar.failed())
        {
          LOGGER.error("Epoch extraction failed: {}", ar.cause().getMessage(), ar.cause());
          safeNak(msg);
          return;
        }

        long epoch = ar.result();
        if (epoch < 0)
        {
          LOGGER.warn("Invalid CA bundle epoch; ignoring message");
          safeAck(msg);
          return;
        }

        scheduleOrQueueRotation(epoch, msgBytes);
        safeAck(msg);
      });
    };
  }

  private Future<Long> extractEpoch(byte[] signedBytes)
  {
    return signedMsgProcessor.obtainDomainObject(signedBytes)
      .compose(payload -> vertx.<Long>executeBlocking(() -> {
        try
        {
          CaBundle ca = CaBundle.deSerialize(payload);
          if (ca == null)
            return -1L;
          return ca.getCaEpochNumber();
        }
        catch (Exception e)
        {
          LOGGER.error("Failed to extract epoch", e);
          return -1L;
        }
      }));
  }

  private void scheduleOrQueueRotation(long epoch, byte[] msgBytes)
  {
    long currentEpochSnapshot = currentEpoch;

    if (epoch <= currentEpochSnapshot)
    {
      LOGGER.info("Ignoring stale CA bundle epoch={} (currentEpoch={})", epoch, currentEpochSnapshot);
      return;
    }

    if (rotationInProgress.compareAndSet(false, true))
    {
      currentEpoch = epoch;
      LOGGER.info("╔═══════════════════════════════════════════════════════════════╗");
      LOGGER.info("║   Starting CA bundle rotation epoch={} (no active rotation)  ║", epoch);
      LOGGER.info("╚═══════════════════════════════════════════════════════════════╝");
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
            LOGGER.info("Queued CA bundle rotation epoch={} (active rotation currentEpoch={})",
                       epoch, currentEpochSnapshot);
            break;
          }
        }
        else if (epoch > prev.epoch)
        {
          if (pendingRotation.compareAndSet(prev, new PendingRotation(epoch, msgBytes)))
          {
            LOGGER.info("Replaced queued rotation epoch={} with newer epoch={}", prev.epoch, epoch);
            break;
          }
        }
        else
        {
          LOGGER.info("Discarding incoming epoch={} (<= queuedEpoch={}) while rotation active",
                     epoch, prev.epoch);
          break;
        }
        prev = pendingRotation.get();
      }
    }
  }

  private void startRotation(long epoch, byte[] msgBytes)
  {
    long startTime = System.currentTimeMillis();

    handleBundleMsg(msgBytes).onComplete(ar -> {
      long elapsed = System.currentTimeMillis() - startTime;

      if (ar.failed())
      {
        LOGGER.error("CA bundle rotation failed epoch={} after {}ms: {}",
                    epoch, elapsed, ar.cause().getMessage(), ar.cause());
      }
      else
      {
        LOGGER.info("╔═══════════════════════════════════════════════════════════════╗");
        LOGGER.info("║ ✅ CA rotation complete epoch={} in {}ms                    ║", epoch, elapsed);
        LOGGER.info("║ New connection active, all pools recreated                   ║");
        LOGGER.info("╚═══════════════════════════════════════════════════════════════╝");
      }

      PendingRotation next = pendingRotation.getAndSet(null);
      if (next != null && next.epoch > currentEpoch)
      {
        LOGGER.info("Promoting queued rotation epoch={} (previous epoch={})", next.epoch, currentEpoch);
        currentEpoch = next.epoch;
        startRotation(next.epoch, next.messageBytes);
        return;
      }

      rotationInProgress.set(false);
    });
  }

  private Future<Void> handleBundleMsg(byte[] signedMsgBytes)
  {
    LOGGER.info("===================================================================================");
    LOGGER.info("CLIENT SERVICE: Processing CA bundle message");
    LOGGER.info("===================================================================================");

    return signedMsgProcessor.obtainDomainObject(signedMsgBytes)
      .compose(requestBytes -> workerExecutor.<CaBundle>executeBlocking(() -> {
        try
        {
          return CaBundle.deSerialize(requestBytes);
        }
        catch (Exception e)
        {
          LOGGER.error("Error deserializing CaBundle: {}", e.getMessage(), e);
          throw new RuntimeException("Failed to deserialize CaBundle", e);
        }
      }))
      .compose(caBundle -> {
        LOGGER.info("Successfully decrypted and verified caBundle - Server: {}, Epoch: {}",
                   caBundle.getServerId(), caBundle.getCaEpochNumber());

        // Step 1: Update Kubernetes secret for persistence
        return workerExecutor.<Void>executeBlocking(() -> {
          caSecretManager.updateCaSecret(caBundle);
          LOGGER.info("✅ Step 1: CA secret updated in Kubernetes");
          return null;
        })
        .compose(v -> {
          // Step 2: Proactive connection recreation
          LOGGER.info("Step 2: Calling NatsTLSClient.handleCaBundleUpdate()");
          LOGGER.info("  → Writes new CA file");
          LOGGER.info("  → Creates new NATS connection with new SSLContext");
          LOGGER.info("  → Recreates all producer/consumer pools");
          LOGGER.info("  → Closes old connection");
          
          return natsTlsClient.handleCaBundleUpdate(caBundle);
        })
        .compose(v -> {
          LOGGER.info("✅ Step 2: CA rotation complete!");
          LOGGER.info("  → New connection active");
          LOGGER.info("  → All pools recreated");
          LOGGER.info("  → Old connection closed");
          return Future.succeededFuture();
        });
      });
  }

  private void safeAck(Message msg)
  {
    try
    {
      msg.ack();
    }
    catch (Exception e)
    {
      LOGGER.warn("ACK failed: {}", e.getMessage());
    }
  }

  private void safeNak(Message msg)
  {
    try
    {
      msg.nak();
    }
    catch (Exception e)
    {
      LOGGER.warn("NAK failed: {}", e.getMessage());
    }
  }
}