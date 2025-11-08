package verticle;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.KeySecretManager;
import core.model.AuthenticationResponse;
import core.nats.NatsTLSClient;
import core.processor.SignedMessageProcessor;
import io.nats.client.JetStreamSubscription;
import io.nats.client.Message;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.json.JsonObject;
import utils.GatekeeperConfig;

/**
 * GatekeeperConsumerVert - Async Pull Consumer Implementation
 * 
 * Consumes authentication responses from service-specific pull consumer
 * and republishes them on the event bus for correlation (gateway.response.received).
 * 
 * @author t-snyder
 * @date 2025-11-04
 */
public class GatekeeperConsumerVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger(GatekeeperConsumerVert.class);

  // Stream configuration
  private static final String STREAM_NAME = "GATEKEEPER_STREAM";
  private static final int BATCH_SIZE = 10;
  private static final long FETCH_TIMEOUT_MS = 500;
  private static final long PULL_INTERVAL_MS = 100;

  // Dependencies
  private final NatsTLSClient natsTlsClient;
  private final GatekeeperConfig gatewayConfig;
  private final KeySecretManager keyCache;
  private final SignedMessageProcessor signedMsgProcessor;

  // Worker pool
  private WorkerExecutor workerExecutor;

  // Subscription
  private JetStreamSubscription responseSubscription;

  // Metrics
  private final AtomicLong messagesReceived = new AtomicLong();
  private final AtomicLong messagesProcessed = new AtomicLong();
  private final AtomicLong messagesFailed = new AtomicLong();
  private long lastMetricLog = System.currentTimeMillis();

  // Simple header cache
  private final Map<String, String> tmpHeaderFlatMap = new ConcurrentHashMap<>();

  public GatekeeperConsumerVert(NatsTLSClient natsTlsClient, 
                                GatekeeperConfig gatewayConfig, 
                                KeySecretManager keyCache, 
                                SignedMessageProcessor signedMsgProcessor)
  {
    this.natsTlsClient = natsTlsClient;
    this.gatewayConfig = gatewayConfig;
    this.keyCache = keyCache;
    this.signedMsgProcessor = signedMsgProcessor;
  }

  @Override
  public void start(Promise<Void> startPromise)
  {
    LOGGER.info("GatekeeperConsumerVert starting with async pull consumer");
    workerExecutor = vertx.createSharedWorkerExecutor("gateway-consumer", 8);
    
    try
    {
      startConsumer()
        .onSuccess(v -> {
          startMetricsReporting();
          LOGGER.info("GatekeeperConsumerVert started successfully with async pull consumer");
          startPromise.complete();
        })
        .onFailure(err -> {
          LOGGER.error("Error starting GatekeeperConsumerVert: {}", err.getMessage(), err);
          cleanup();
          startPromise.fail(err);
        });
    }
    catch(Exception e)
    {
      LOGGER.error("Error starting GatekeeperConsumerVert: {}", e.getMessage(), e);
      cleanup();
      startPromise.fail(e);
    }
  }

  @Override
  public void stop(Promise<Void> stopPromise)
  {
    LOGGER.info("Stopping GatekeeperConsumerVert");
    cleanup();
    stopPromise.complete();
  }

  /**
   * Bind to async pull consumer for gatekeeper responses
   */
  private Future<Void> startConsumer()
  {
    LOGGER.info("Binding to gatekeeper response async pull consumer: stream={}", STREAM_NAME);

    Promise<Void> promise = Promise.promise();
    
    String durableName = "gatekeeper-responder-consumer";

    natsTlsClient.getConsumerPoolManager().bindPullConsumerAsync(
      STREAM_NAME,
      durableName,
      this::handleAuthResponseAsync,  // ASYNC handler - returns Future<Void>
      BATCH_SIZE,
      FETCH_TIMEOUT_MS,
      PULL_INTERVAL_MS
    )
    .onSuccess(sub -> {
      this.responseSubscription = sub;
      LOGGER.info("Bound to gatekeeper response async pull consumer: durable={}", durableName);
      promise.complete();
    })
    .onFailure(err -> {
      LOGGER.error("Failed to bind async gatekeeper-responder consumer: {}", err.getMessage(), err);
      promise.fail(err);
    });

    return promise.future();
  }

  /**
   * Handle auth response message - ASYNC VERSION
   * Returns Future that completes when processing is done
   */
  private Future<Void> handleAuthResponseAsync(Message msg)
  {
    Promise<Void> promise = Promise.promise();
    
    try
    {
      messagesReceived.incrementAndGet();

      String messageKey = extractMessageKey(msg);
      
      // Process the response asynchronously
      processAuthResponse(msg.getData())
        .onComplete(ar -> {
          if (ar.succeeded())
          {
            messagesProcessed.incrementAndGet();
            
            // Forward to event bus for HTTP correlation
            JsonObject eventBusMsg = new JsonObject()
              .put("messageKey", messageKey)
              .put("messageBody", msg.getData())
              .put("properties", headersToJson(msg))
              .put("messageId", "nats-" + System.nanoTime())
              .put("publishTime", System.currentTimeMillis());

            vertx.eventBus().publish("gateway.response.received", eventBusMsg);
            
            LOGGER.debug("Processed and forwarded auth response: {}", messageKey);
            promise.complete();
          }
          else
          {
            messagesFailed.incrementAndGet();
            LOGGER.error("Failed to process auth response {}: {}", 
                        messageKey, ar.cause().getMessage(), ar.cause());
            promise.fail(ar.cause());
          }
        });
    }
    catch (Exception e)
    {
      LOGGER.error("Exception in handleAuthResponseAsync: {}", e.getMessage(), e);
      messagesFailed.incrementAndGet();
      promise.fail(e);
    }
    
    return promise.future();
  }

  /**
   * Extract message key from headers
   */
  private String extractMessageKey(Message msg)
  {
    try
    {
      Object raw = msg.getHeaders();
      if(raw != null)
      {
        Map<String, String> flat = extractHeadersFlat(msg);
        String hk = flat.get("messageKey");
        if(hk != null && !hk.isBlank())
          return hk;
      }
    }
    catch(Throwable t)
    {
      LOGGER.debug("Failed to extract message key: {}", t.getMessage());
    }
    
    // Fallback: generated key
    return "nats-" + System.nanoTime();
  }

  /**
   * Extract headers as flat map
   */
  private Map<String, String> extractHeadersFlat(Message msg)
  {
    tmpHeaderFlatMap.clear();
    try
    {
      Object raw = msg.getHeaders();
      if(raw == null)
        return Map.copyOf(tmpHeaderFlatMap);

      if(raw instanceof Map<?, ?>)
      {
        @SuppressWarnings("unchecked")
        Map<String, java.util.List<String>> cast = (Map<String, java.util.List<String>>)raw;
        cast.forEach((k, v) -> {
          if(k == null) return;
          if(v == null || v.isEmpty())
            tmpHeaderFlatMap.put(k, "");
          else if(v.size() == 1)
            tmpHeaderFlatMap.put(k, v.get(0));
          else
            tmpHeaderFlatMap.put(k, String.join(",", v));
        });
      }
    }
    catch(Throwable ignore)
    {
      LOGGER.debug("Failed to extract headers: {}", ignore.getMessage());
    }

    return Map.copyOf(tmpHeaderFlatMap);
  }

  /**
   * Convert headers to JsonObject
   */
  private JsonObject headersToJson(Message msg)
  {
    JsonObject json = new JsonObject();
    try
    {
      Map<String, String> flat = extractHeadersFlat(msg);
      flat.forEach(json::put);
    }
    catch(Throwable ignore)
    {
      // Return empty JSON object if headers can't be read
    }
    return json;
  }

  /**
   * Process auth response - decrypt and verify - ASYNC
   */
  private Future<Void> processAuthResponse(byte[] data)
  {
    return signedMsgProcessor.obtainDomainObject(data)
      .map(o -> (byte[])o)
      .compose(bytes -> workerExecutor.<AuthenticationResponse>executeBlocking(() -> 
        AuthenticationResponse.deserialize(bytes)
      ))
      .mapEmpty();
  }

  /**
   * Start metrics reporting timer
   */
  private void startMetricsReporting()
  {
    vertx.setPeriodic(60000, id -> {
      long now = System.currentTimeMillis();
      if(now - lastMetricLog >= 60000)
      {
        long r = messagesReceived.get();
        long p = messagesProcessed.get();
        long f = messagesFailed.get();
        long elapsed = now - lastMetricLog;
        long rate = elapsed > 0 ? (r * 60000 / elapsed) : 0;

        LOGGER.info("Gateway Consumer Metrics - received={} processed={} failed={} rate={}/min", 
                   r, p, f, rate);
        lastMetricLog = now;
      }
    });
  }

  /**
   * Cleanup resources
   */
  private void cleanup()
  {
    LOGGER.info("GatekeeperConsumerVert cleanup - start");
    
    if(responseSubscription != null)
    {
      try
      {
        responseSubscription.drain(Duration.ofSeconds(2));
        responseSubscription.unsubscribe();
      }
      catch(Exception e)
      {
        LOGGER.warn("Failed to unsubscribe: {}", e.getMessage(), e);
      }
      responseSubscription = null;
    }

    if(workerExecutor != null)
    {
      try
      {
        workerExecutor.close();
      }
      catch(Exception e)
      {
        LOGGER.warn("Error closing worker executor: {}", e.getMessage());
      }
    }
    
    LOGGER.info("GatekeeperConsumerVert cleanup - complete");
  }

  // Metrics getters
  public long getMessagesReceived() { return messagesReceived.get(); }
  public long getMessagesProcessed() { return messagesProcessed.get(); }
  public long getMessagesFailed() { return messagesFailed.get(); }
}