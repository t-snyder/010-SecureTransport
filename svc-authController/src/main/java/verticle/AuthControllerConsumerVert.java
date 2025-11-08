package verticle;

import core.model.AuthenticationRequest;
import core.nats.NatsTLSClient;
import core.processor.SignedMessageProcessor;
import io.nats.client.JetStreamSubscription;
import io.nats.client.Message;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utils.AuthControllerConfig;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * AuthController Consumer - Async Pull Consumer Implementation
 * 
 * Fetches authentication requests from service-specific pull consumer.
 * Processes SignedMessage, decrypts/verifies to get AuthenticationRequest,
 * then forwards to producer via event bus.
 * 
 * @author t-snyder
 * @date 2025-11-04
 */
public class AuthControllerConsumerVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger(AuthControllerConsumerVert.class);

  // Stream configuration
  private static final String STREAM_NAME = "AUTH_STREAM";
  private static final int BATCH_SIZE = 10;
  private static final long FETCH_TIMEOUT_MS = 500;
  private static final long PULL_INTERVAL_MS = 100;

  // Event bus addresses
  private static final String AUTH_REQUEST_BUS_ADDR = "authcontroller.process.request";
  private static final String METRICS_BUS_ADDR = "authcontroller.metrics";
  private static final String DOWNTIME_START_BUS_ADDR = "authcontroller.downtime.start";
  private static final String DOWNTIME_END_BUS_ADDR = "authcontroller.downtime.end";

  // Dependencies
  private final NatsTLSClient natsTlsClient;
  private final SignedMessageProcessor signedMsgProcessor;
  private final AuthControllerConfig authConfig;

  // Worker pool
  private WorkerExecutor workerExecutor;

  // Subscription
  private JetStreamSubscription requestSubscription;

  // Metrics and Counters
  private final AtomicLong messagesReceived = new AtomicLong();
  private final AtomicLong messagesProcessed = new AtomicLong();
  private final AtomicLong messagesFailed = new AtomicLong();
  private final AtomicLong downtimeEvents = new AtomicLong();
  
  // Receipt counter - tracks each message received by this consumer
  private final AtomicLong messageReceiptCounter = new AtomicLong(0);
  private long lastReceiptCounterLog = 0;

  private volatile boolean isHealthy = true;
  private long lastDowntimeStart = 0;
  private String lastDowntimeReason = null;
  private long lastMetricLog = System.currentTimeMillis();

  // Config
  private String responseSubject;

  // Simple header cache to avoid repeated allocations
  private final Map<String, String> tmpHeaderFlatMap = new ConcurrentHashMap<>();

  public AuthControllerConsumerVert(NatsTLSClient natsTlsClient, 
                                   SignedMessageProcessor signedMsgProcessor, 
                                   AuthControllerConfig authConfig)
  {
    this.natsTlsClient = natsTlsClient;
    this.signedMsgProcessor = signedMsgProcessor;
    this.authConfig = authConfig;
  }

  @Override
  public void start(Promise<Void> startPromise)
  {
    try
    {
      LOGGER.info("AuthControllerConsumerVert starting with async pull consumer");
      initConfig();
      workerExecutor = vertx.createSharedWorkerExecutor("authcontroller-consumer", 8);
      
      // Bind to async pull consumer for auth requests
      startAuthRequestConsumer()
        .onSuccess(v -> {
          markHealthy("Subscription established");
          startMetricsTimer();
          startHealthTimer();
          LOGGER.info("AuthController async pull consumer started: stream={} durable=auth-requests", 
                     STREAM_NAME);
          startPromise.complete();
        })
        .onFailure(err -> {
          recordDowntime("Startup failure: " + err.getMessage());
          startPromise.fail(err);
        });
    }
    catch(Exception e)
    {
      recordDowntime("Startup exception: " + e.getMessage());
      startPromise.fail(e);
    }
  }

  @Override
  public void stop(Promise<Void> stopPromise)
  {
    LOGGER.info("Stopping AuthControllerConsumerVert");
    cleanup();
    stopPromise.complete();
  }

  /**
   * Initialize configuration
   */
  private void initConfig()
  {
    this.responseSubject = authConfig.getGatekeeperResponseTopic();
  }

  /**
   * Bind to async pull consumer for auth requests
   */
  private Future<Void> startAuthRequestConsumer()
  {
    LOGGER.info("Binding to auth request async pull consumer: stream={}", STREAM_NAME);

    Promise<Void> promise = Promise.promise();
    
    String durableName = "auth-requests";

    natsTlsClient.getConsumerPoolManager().bindPullConsumerAsync(
      STREAM_NAME,
      durableName,
      this::handleAuthRequestAsync,  // ASYNC handler - returns Future<Void>
      BATCH_SIZE,
      FETCH_TIMEOUT_MS,
      PULL_INTERVAL_MS
    )
    .onSuccess(sub -> {
      this.requestSubscription = sub;
      LOGGER.info("Bound to auth request async pull consumer: durable={}", durableName);
      promise.complete();
    })
    .onFailure(err -> {
      LOGGER.error("Failed to bind async auth-requests consumer: {}", err.getMessage(), err);
      promise.fail(err);
    });

    return promise.future();
  }

  /**
   * Handle auth request message - ASYNC VERSION
   * Returns Future that completes when processing is done
   */
  private Future<Void> handleAuthRequestAsync(Message msg)
  {
    Promise<Void> promise = Promise.promise();
    
    try
    {
      messagesReceived.incrementAndGet();
      
      // Increment receipt counter for this message
      long receiptCounter = messageReceiptCounter.incrementAndGet();
      
      // Derive message key
      String messageKey = extractMessageKey(msg);
      String originalId = messageKey;
      long requestTimestamp = System.currentTimeMillis();

      Map<String, String> properties = extractHeadersFlat(msg);
      
      // Extract generation counter from headers
      String genCounterStr = properties.get("generationCounter");
      Long generationCounter = null;
      if(genCounterStr != null)
      {
        try
        {
          generationCounter = Long.parseLong(genCounterStr);
        }
        catch(NumberFormatException e)
        {
          LOGGER.debug("Failed to parse generationCounter: {}", genCounterStr);
        }
      }

      // Log counters every 100 messages
      logReceiptCounterIfNeeded(receiptCounter, generationCounter);

      // Process the request asynchronously
      processAuthenticationRequestAsync(msg.getData(), messageKey, properties, 
                                       originalId, requestTimestamp, 
                                       receiptCounter, generationCounter)
        .onComplete(ar -> {
          if (ar.succeeded())
          {
            messagesProcessed.incrementAndGet();
            if(!isHealthy)
              markHealthy("Processing resumed");
            LOGGER.debug("Processed auth request: {}", messageKey);
            promise.complete();
          }
          else
          {
            messagesFailed.incrementAndGet();
            LOGGER.error("Failed to process auth request {}: {}", 
                        messageKey, ar.cause().getMessage(), ar.cause());
            promise.fail(ar.cause());
          }
        });
    }
    catch (Exception e)
    {
      LOGGER.error("Exception in handleAuthRequestAsync: {}", e.getMessage(), e);
      messagesFailed.incrementAndGet();
      promise.fail(e);
    }
    
    return promise.future();
  }

  private void logReceiptCounterIfNeeded(long receiptCounter, Long generationCounter)
  {
    // Log every 100 messages
    if(receiptCounter - lastReceiptCounterLog >= 100)
    {
      if(generationCounter != null)
      {
        LOGGER.info("========== AUTHCONTROLLER MESSAGE RECEIPT: ReceiptCounter = {}, GenerationCounter = {} ==========", 
            receiptCounter, generationCounter);
      }
      else
      {
        LOGGER.info("========== AUTHCONTROLLER MESSAGE RECEIPT: ReceiptCounter = {}, GenerationCounter = N/A ==========", 
            receiptCounter);
      }
      lastReceiptCounterLog = receiptCounter;
    }
  }

  /**
   * Process the incoming NATS message - ASYNC
   * 1. Deserialize SignedMessage from raw bytes
   * 2. Use SignedMessageProcessor to decrypt/verify and obtain AuthenticationRequest bytes
   * 3. Deserialize AuthenticationRequest from Avro bytes
   * 4. Serialize AuthenticationRequest back to Avro for event bus transmission
   * 5. Publish to event bus for producer to handle (including counters)
   */
  private Future<Void> processAuthenticationRequestAsync(byte[] messageData, 
                                                         String messageKey, 
                                                         Map<String, String> properties, 
                                                         String originalMessageId, 
                                                         long requestTimestamp, 
                                                         long receiptCounter, 
                                                         Long generationCounter)
  {
    // Step 1: Process SignedMessage to get decrypted/verified AuthenticationRequest bytes
    return signedMsgProcessor.obtainDomainObject(messageData)
      // Step 2: Deserialize AuthenticationRequest from the decrypted bytes
      .compose(authRequestBytes -> workerExecutor.<AuthenticationRequest>executeBlocking(() -> 
        AuthenticationRequest.deserialize(authRequestBytes)
      ))
      // Step 3: Serialize AuthenticationRequest back to Avro for event bus
      .compose(authRequest -> workerExecutor.<byte[]>executeBlocking(() -> 
        authRequest.serialize()
      ))
      // Step 4: Publish to event bus for AuthControllerProducerVert to process
      .onSuccess(serializedAuthRequest -> 
        publishAuthRequestToEventBus(messageKey, originalMessageId, serializedAuthRequest, 
                                    properties, requestTimestamp, receiptCounter, 
                                    generationCounter)
      )
      .mapEmpty();
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
      LOGGER.debug("Failed to extract message key from headers: {}", t.getMessage());
    }

    return "msg-" + System.nanoTime();
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
        return Map.copyOf(tmpHeaderFlatMap);
      }
    }
    catch(Throwable ignore)
    {
      LOGGER.debug("Failed to extract headers: {}", ignore.getMessage());
    }

    return Map.copyOf(tmpHeaderFlatMap);
  }

  /**
   * Publish serialized AuthenticationRequest to event bus for producer to handle
   */
  private void publishAuthRequestToEventBus(String messageKey, 
                                           String originalMessageId, 
                                           byte[] serializedAuthRequest, 
                                           Map<String, String> properties, 
                                           long requestTimestamp,
                                           long receiptCounter, 
                                           Long generationCounter)
  {
    JsonObject propsJson = new JsonObject();
    properties.forEach(propsJson::put);

    JsonObject requestJson = new JsonObject()
      .put("messageKey", messageKey)
      .put("originalMessageId", originalMessageId)
      .put("authRequestBytes", serializedAuthRequest)
      .put("properties", propsJson)
      .put("requestTimestamp", requestTimestamp)
      .put("topic", responseSubject)
      .put("receiptCounter", receiptCounter);
    
    // Add generationCounter if available
    if(generationCounter != null)
    {
      requestJson.put("generationCounter", generationCounter);
    }

    vertx.eventBus().publish(AUTH_REQUEST_BUS_ADDR, requestJson);
    LOGGER.debug("Published AuthenticationRequest to event bus for messageKey: {}", messageKey);
  }

  /**
   * Start metrics timer
   */
  private void startMetricsTimer()
  {
    vertx.setPeriodic(60000, id -> {
      long now = System.currentTimeMillis();
      if(now - lastMetricLog >= 60000)
      {
        long received = messagesReceived.get();
        long processed = messagesProcessed.get();
        long failed = messagesFailed.get();
        long downtime = downtimeEvents.get();
        long elapsed = now - lastMetricLog;
        long ratePerMin = elapsed > 0 ? (received * 60000 / elapsed) : 0;

        LOGGER.info("AuthController Consumer Metrics - received={} processed={} failed={} downtime={} rate={}/min health={}", 
            received, processed, failed, downtime, ratePerMin, isHealthy ? "HEALTHY" : "UNHEALTHY");

        vertx.eventBus().publish(METRICS_BUS_ADDR, new JsonObject()
          .put("messagesReceived", received)
          .put("messagesProcessed", processed)
          .put("messagesFailed", failed)
          .put("downtimeEvents", downtime)
          .put("isHealthy", isHealthy)
          .put("lastDowntimeReason", lastDowntimeReason)
          .put("timestamp", now));

        lastMetricLog = now;
      }
    });
  }

  /**
   * Start health check timer
   */
  private void startHealthTimer()
  {
    vertx.setPeriodic(30000, id -> {
      try
      {
        if(natsTlsClient.isHealthy())
        {
          if(!isHealthy)
            markHealthy("Health check recovered");
        }
        else
        {
          if(isHealthy)
            recordDowntime("NATS connection unhealthy");
        }
      }
      catch(Exception e)
      {
        if(isHealthy)
          recordDowntime("Health check error: " + e.getMessage());
      }
    });
  }

  /**
   * Record downtime event
   */
  private void recordDowntime(String reason)
  {
    if(isHealthy)
    {
      isHealthy = false;
      lastDowntimeStart = System.currentTimeMillis();
      lastDowntimeReason = reason;
      downtimeEvents.incrementAndGet();
      LOGGER.warn("Consumer downtime started reason={}", reason);
      vertx.eventBus().publish(DOWNTIME_START_BUS_ADDR, new JsonObject()
        .put("reason", reason)
        .put("timestamp", lastDowntimeStart)
        .put("serviceId", "authcontroller")
        .put("component", "consumer"));
    }
  }

  /**
   * Mark service as healthy
   */
  private void markHealthy(String reason)
  {
    if(!isHealthy)
    {
      long duration = System.currentTimeMillis() - lastDowntimeStart;
      isHealthy = true;
      LOGGER.info("Consumer service recovered downtimeMs={} reason={}", duration, reason);
      vertx.eventBus().publish(DOWNTIME_END_BUS_ADDR, new JsonObject()
        .put("recoveryReason", reason)
        .put("downtimeDuration", duration)
        .put("timestamp", System.currentTimeMillis())
        .put("serviceId", "authcontroller")
        .put("component", "consumer"));
      lastDowntimeReason = null;
    }
  }

  /**
   * Cleanup resources
   */
  private void cleanup()
  {
    LOGGER.info("AuthControllerConsumerVert cleanup - start");
    try
    {
      if(requestSubscription != null)
      {
        try
        {
          requestSubscription.drain(Duration.ofSeconds(2));
          requestSubscription.unsubscribe();
        }
        catch(Exception e)
        {
          LOGGER.debug("Unsubscribe error: {}", e.getMessage());
        }
        requestSubscription = null;
      }
      
      if(workerExecutor != null)
      {
        workerExecutor.close();
      }
    }
    catch(Exception e)
    {
      LOGGER.warn("Cleanup partial failure: {}", e.getMessage());
    }
    LOGGER.info("AuthControllerConsumerVert cleanup - complete");
  }
  
  // Metrics getters
  public long getMessagesReceived() { return messagesReceived.get(); }
  public long getMessagesProcessed() { return messagesProcessed.get(); }
  public long getMessagesFailed() { return messagesFailed.get(); }
  public long getDowntimeEvents() { return downtimeEvents.get(); }
  public boolean isHealthy() { return isHealthy; }
  public String getLastDowntimeReason() { return lastDowntimeReason; }
  public long getMessageReceiptCounter() { return messageReceiptCounter.get(); }
}