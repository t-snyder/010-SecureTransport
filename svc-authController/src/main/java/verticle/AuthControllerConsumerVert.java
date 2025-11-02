package verticle;

import core.model.AuthenticationRequest;
import core.nats.NatsConsumerErrorHandler;
import core.nats.NatsTLSClient;
import core.processor.SignedMessageProcessor;
import io.nats.client.JetStreamSubscription;
import io.nats.client.Message;
import io.nats.client.MessageHandler;
import io.nats.client.Subscription;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utils.AuthControllerConfig;

import java.time.Duration;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * AuthController consumer that properly processes SignedMessage,
 * decrypts/verifies to get AuthenticationRequest, then forwards
 * the serialized request via event bus.
 * 
 * Tracks message receipt counter and extracts generation counter from headers.
 */
public class AuthControllerConsumerVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger( AuthControllerConsumerVert.class );

  // Event bus addresses
  private static final String AUTH_REQUEST_BUS_ADDR = "authcontroller.process.request";
  private static final String METRICS_BUS_ADDR = "authcontroller.metrics";
  private static final String DOWNTIME_START_BUS_ADDR = "authcontroller.downtime.start";
  private static final String DOWNTIME_END_BUS_ADDR = "authcontroller.downtime.end";

  // Dependencies
  private final NatsTLSClient natsTlsClient;
  private final SignedMessageProcessor signedMsgProcessor;
  private final AuthControllerConfig authConfig;
  private final NatsConsumerErrorHandler errHandler = new NatsConsumerErrorHandler();

  // Worker pool
  private WorkerExecutor workerExecutor;

  // Subscription
  private volatile Subscription requestSubscription;

  // Metrics and Counters
  private final AtomicLong messagesReceived  = new AtomicLong();
  private final AtomicLong messagesProcessed = new AtomicLong();
  private final AtomicLong messagesFailed = new AtomicLong();
  private final AtomicLong downtimeEvents = new AtomicLong();
  private final AtomicLong localSeq = new AtomicLong();
  
  // Receipt counter - tracks each message received by this consumer
  private final AtomicLong messageReceiptCounter = new AtomicLong( 0 );
  private long lastReceiptCounterLog = 0;

  private volatile boolean isHealthy = true;
  private long lastDowntimeStart = 0;
  private String lastDowntimeReason = null;
  private long lastMetricLog = System.currentTimeMillis();

  // Config / subjects
  private String requestSubject;
  private String responseSubject;
  private String queueGroupName = "authcontroller-requests";

  // Simple header cache to avoid repeated allocations (optional)
  private final Map<String, String> tmpHeaderFlatMap = new ConcurrentHashMap<>();

  public AuthControllerConsumerVert( NatsTLSClient natsTlsClient, SignedMessageProcessor signedMsgProcessor, AuthControllerConfig authConfig )
  {
    this.natsTlsClient = natsTlsClient;
    this.signedMsgProcessor = signedMsgProcessor;
    this.authConfig = authConfig;
  }

  @Override
  public void start( Promise<Void> startPromise )
  {
    try
    {
      LOGGER.info( "AuthControllerConsumerVert.start() - initializing" );
      initConfig();
      workerExecutor = vertx.createSharedWorkerExecutor( "authcontroller-consumer", 8 );
      
      // Attach to push-mode durable (join queue)
      natsTlsClient.attachPushQueue(requestSubject, queueGroupName, messageHandler())
        .onSuccess( sub -> {
          requestSubscription = sub; // no cast
          markHealthy( "Subscription established" );
          startMetricsTimer();
          startHealthTimer();
          LOGGER.info( "AuthController consumer started on subject {}", requestSubject );
          startPromise.complete();
        })
        .onFailure( err -> {
          recordDowntime( "Startup failure: " + err.getMessage() );
          startPromise.fail( err );
        } );
    }
    catch( Exception e )
    {
      recordDowntime( "Startup exception: " + e.getMessage() );
      startPromise.fail( e );
    }
  }

  @Override
  public void stop( Promise<Void> stopPromise )
  {
    LOGGER.info( "AuthControllerConsumerVert.stop() - shutting down" );
    cleanup();
    stopPromise.complete();
  }
  
  private void initConfig()
  {
    this.requestSubject  = authConfig.getGatekeeperRequestTopic();
    this.responseSubject = authConfig.getGatekeeperResponseTopic();
  }

  private MessageHandler messageHandler()
  {
    return this::onMessage;
  }

  private void onMessage( Message msg )
  {
    if( msg == null )
      return;
    
    messagesReceived.incrementAndGet();
    
    // Increment receipt counter for this message
    long receiptCounter = messageReceiptCounter.incrementAndGet();
    
    // Derive message key
    String messageKey = extractMessageKey( msg );
    String originalId = messageKey;
    long requestTimestamp = System.currentTimeMillis();

    Map<String, String> properties = extractHeadersFlat( msg );
    
    // Extract generation counter from headers
    String genCounterStr = properties.get( "generationCounter" );
    Long generationCounter = null;
    if( genCounterStr != null )
    {
      try
      {
        generationCounter = Long.parseLong( genCounterStr );
      }
      catch( NumberFormatException e )
      {
        LOGGER.debug( "Failed to parse generationCounter: {}", genCounterStr );
      }
    }

    // Log counters every 100 messages
    logReceiptCounterIfNeeded( receiptCounter, generationCounter );

    processAuthenticationRequestAsync( msg.getData(), messageKey, properties, originalId, requestTimestamp, receiptCounter, generationCounter )
        .onComplete( ar -> {
          if( ar.succeeded() )
          {
            ackQuiet( msg );
            messagesProcessed.incrementAndGet();
            if( !isHealthy )
              markHealthy( "Processing resumed" );
          }
          else
          {
            messagesFailed.incrementAndGet();
            Throwable cause = ar.cause();

            // Simple retry path: NAK (JetStream server will redeliver if configured)
            nakQuiet( msg );

            if( errHandler.isUnrecoverableError( cause ) )
            {
              recordDowntime( "Unrecoverable error: " + cause.getMessage() );
            }

            LOGGER.error( "Failed to process authentication request: {}", cause != null ? cause.getMessage() : "Unknown error", cause );
          }
        } );
  }

  private void logReceiptCounterIfNeeded( long receiptCounter, Long generationCounter )
  {
    // Log every 100 messages
    if( receiptCounter - lastReceiptCounterLog >= 100 )
    {
      if( generationCounter != null )
      {
        LOGGER.info( "========== AUTHCONTROLLER MESSAGE RECEIPT: ReceiptCounter = {}, GenerationCounter = {} ==========", 
            receiptCounter, generationCounter );
      }
      else
      {
        LOGGER.info( "========== AUTHCONTROLLER MESSAGE RECEIPT: ReceiptCounter = {}, GenerationCounter = N/A ==========", 
            receiptCounter );
      }
      lastReceiptCounterLog = receiptCounter;
    }
  }

  // -------- Processing Pipeline --------
  /**
   * Process the incoming NATS message:
   * 1. Deserialize SignedMessage from raw bytes
   * 2. Use SignedMessageProcessor to decrypt/verify and obtain AuthenticationRequest bytes
   * 3. Deserialize AuthenticationRequest from Avro bytes
   * 4. Serialize AuthenticationRequest back to Avro for event bus transmission
   * 5. Publish to event bus for producer to handle (including counters)
   */
  private Future<Void> processAuthenticationRequestAsync( byte[] messageData, String messageKey, Map<String, String> properties, 
                                                          String originalMessageId, long requestTimestamp, 
                                                          long receiptCounter, Long generationCounter )
  {
    // Step 1: Process SignedMessage to get decrypted/verified AuthenticationRequest bytes
    return signedMsgProcessor.obtainDomainObject( messageData )
        // Step 2: Deserialize AuthenticationRequest from the decrypted bytes
        .compose( authRequestBytes -> workerExecutor.<AuthenticationRequest> executeBlocking( () -> 
            AuthenticationRequest.deserialize( authRequestBytes ) 
        ))
        // Step 3: Serialize AuthenticationRequest back to Avro for event bus
        .compose( authRequest -> workerExecutor.<byte[]> executeBlocking( () -> 
            authRequest.serialize() 
        ))
        // Step 4: Publish to event bus for AuthControllerProducerVert to process
        .onSuccess( serializedAuthRequest -> 
            publishAuthRequestToEventBus( messageKey, originalMessageId, serializedAuthRequest, properties, 
                                         requestTimestamp, receiptCounter, generationCounter ) 
        )
        .transform( ar -> {
          if( ar.succeeded() )
            return Future.succeededFuture();
          LOGGER.error( "Error in authentication request pipeline: {}", ar.cause() != null ? ar.cause().getMessage() : "Unknown" );
          return Future.failedFuture( ar.cause() );
        } );
  }

  // -------- Helpers: Headers / Key / ACK/NACK --------
  private String extractMessageKey( Message msg )
  {
    try
    {
      Object raw = msg.getHeaders();
      if( raw != null )
      {
        try
        {
          java.lang.reflect.Method getFirst = raw.getClass().getMethod( "getFirst", String.class );
          Object v = getFirst.invoke( raw, "messageKey" );
          if( v instanceof String s && !s.isBlank() )
            return s;
        }
        catch( NoSuchMethodException ignored )
        {
        }
        Map<String, String> flat = extractHeadersFlat( msg );
        String hk = flat.get( "messageKey" );
        if( hk != null && !hk.isBlank() )
          return hk;
      }
    }
    catch( Throwable t )
    {
      LOGGER.debug( "Failed to extract message key from headers: {}", t.getMessage() );
    }

    long seq = localSeq.incrementAndGet();
    return "msg-" + seq;
  }
  
  private Map<String, String> extractHeadersFlat( Message msg )
  {
    tmpHeaderFlatMap.clear();
    try
    {
      Object raw = msg.getHeaders();
      if( raw == null )
        return Map.copyOf( tmpHeaderFlatMap );

      // Case A: some runtimes return a Map<String, List<String>>
      if( raw instanceof Map<?, ?> )
      {
        @SuppressWarnings( "unchecked" )
        Map<String, java.util.List<String>> cast = (Map<String, java.util.List<String>>)raw;
        cast.forEach( ( k, v ) -> {
          if( k == null )
            return;
          if( v == null || v.isEmpty() )
            tmpHeaderFlatMap.put( k, "" );
          else if( v.size() == 1 )
            tmpHeaderFlatMap.put( k, v.get( 0 ) );
          else
            tmpHeaderFlatMap.put( k, String.join( ",", v ) );
        } );
        return Map.copyOf( tmpHeaderFlatMap );
      }

      // Case B: reflective handling for Headers-like object (jnats internal impl)
      try
      {
        Class<?> hdrClass = raw.getClass();

        // Try to obtain a collection of keys: names() or keySet()
        java.util.Collection<String> keys = null;
        try
        {
          var namesM = hdrClass.getMethod( "names" );
          Object res = namesM.invoke( raw );
          if( res instanceof Collection )
            keys = (Collection<String>)res;
        }
        catch( NoSuchMethodException ignored )
        {
        }
        if( keys == null )
        {
          try
          {
            var keySetM = hdrClass.getMethod( "keySet" );
            Object res = keySetM.invoke( raw );
            if( res instanceof java.util.Collection )
              keys = (java.util.Collection<String>)res;
          }
          catch( NoSuchMethodException ignored )
          {
          }
        }

        // Try to read single-value accessor getFirst(String)
        java.lang.reflect.Method getFirst = null;
        try
        {
          getFirst = hdrClass.getMethod( "getFirst", String.class );
        }
        catch( NoSuchMethodException ignored )
        {
        }

        // Try toMap() or toMapUtf8() style helpers if present
        java.lang.reflect.Method toMap = null;
        if( getFirst == null || keys == null )
        {
          try
          {
            toMap = hdrClass.getMethod( "toMap" );
          }
          catch( NoSuchMethodException ignored )
          {
          }
          if( toMap == null )
          {
            try
            {
              toMap = hdrClass.getMethod( "asMap" );
            }
            catch( NoSuchMethodException ignored )
            {
            }
          }
        }

        if( toMap != null )
        {
          Object maybeMap = toMap.invoke( raw );
          if( maybeMap instanceof Map<?, ?> )
          {
            @SuppressWarnings( "unchecked" )
            Map<String, java.util.List<String>> cast = (Map<String, java.util.List<String>>)maybeMap;
            cast.forEach( ( k, v ) ->
            {
              if( k == null )
                return;
              if( v == null || v.isEmpty() )
                tmpHeaderFlatMap.put( k, "" );
              else if( v.size() == 1 )
                tmpHeaderFlatMap.put( k, v.get( 0 ) );
              else
                tmpHeaderFlatMap.put( k, String.join( ",", v ) );
            } );
            return Map.copyOf( tmpHeaderFlatMap );
          }
        }

        // If we have keys and getFirst, iterate keys->getFirst
        if( keys != null && getFirst != null )
        {
          for( String k : keys )
          {
            if( k == null )
              continue;
            try
            {
              Object val = getFirst.invoke( raw, k );
              tmpHeaderFlatMap.put( k, val == null ? "" : String.valueOf( val ) );
            }
            catch( Throwable t )
            {
              // ignore individual header read failures
            }
          }
          return Map.copyOf( tmpHeaderFlatMap );
        }

        // Last-resort: try generic "get" method returning List<String> or String
        try
        {
          var getM = hdrClass.getMethod( "get", String.class );
          if( keys != null )
          {
            for( String k : keys )
            {
              if( k == null )
                continue;
              try
              {
                Object v = getM.invoke( raw, k );
                if( v instanceof java.util.List )
                {
                  @SuppressWarnings( "unchecked" )
                  java.util.List<String> lv = (java.util.List<String>)v;
                  if( lv.isEmpty() )
                    tmpHeaderFlatMap.put( k, "" );
                  else if( lv.size() == 1 )
                    tmpHeaderFlatMap.put( k, lv.get( 0 ) );
                  else
                    tmpHeaderFlatMap.put( k, String.join( ",", lv ) );
                }
                else
                {
                  tmpHeaderFlatMap.put( k, v == null ? "" : String.valueOf( v ) );
                }
              }
              catch( Throwable t )
              {
                /* ignore per-key errors */ }
            }
            return Map.copyOf( tmpHeaderFlatMap );
          }
        }
        catch( NoSuchMethodException ignored )
        {
        }

      }
      catch( Throwable reflEx )
      {
        LOGGER.debug( "Header reflective extraction failed: {}", reflEx.getMessage() );
      }
    }
    catch( Throwable ignore )
    {
      LOGGER.debug( "Failed to extract headers: {}", ignore.getMessage() );
    }

    return Map.copyOf( tmpHeaderFlatMap );
  }

  private void ackQuiet( Message msg )
  {
    try
    {
      msg.ack();
    }
    catch( Throwable t )
    {
      LOGGER.debug( "Ack ignored/failed: {}", t.getMessage() );
    }
  }

  private void nakQuiet( Message msg )
  {
    try
    {
      msg.nak();
    }
    catch( Throwable t )
    {
      LOGGER.debug( "Nak ignored/failed: {}", t.getMessage() );
    }
  }

  // -------- Event Bus Publishing --------
  /**
   * Publish serialized AuthenticationRequest to event bus for producer to handle
   */
  private void publishAuthRequestToEventBus( String messageKey, String originalMessageId, byte[] serializedAuthRequest, 
                                             Map<String, String> properties, long requestTimestamp,
                                             long receiptCounter, Long generationCounter )
  {
    JsonObject propsJson = new JsonObject();
    properties.forEach( propsJson::put );

    JsonObject requestJson = new JsonObject()
        .put( "messageKey", messageKey )
        .put( "originalMessageId", originalMessageId )
        .put( "authRequestBytes", serializedAuthRequest )
        .put( "properties", propsJson )
        .put( "requestTimestamp", requestTimestamp )
        .put( "topic", responseSubject )
        .put( "receiptCounter", receiptCounter );
    
    // Add generationCounter if available
    if( generationCounter != null )
    {
      requestJson.put( "generationCounter", generationCounter );
    }

    vertx.eventBus().publish( AUTH_REQUEST_BUS_ADDR, requestJson );
    LOGGER.debug( "Published AuthenticationRequest to event bus for messageKey: {}", messageKey );
  }

  // -------- Metrics & Health --------
  private void startMetricsTimer()
  {
    vertx.setPeriodic( 60000, id -> {
      long now = System.currentTimeMillis();
      if( now - lastMetricLog >= 60000 )
      {
        long received = messagesReceived.get();
        long processed = messagesProcessed.get();
        long failed = messagesFailed.get();
        long downtime = downtimeEvents.get();
        long elapsed = now - lastMetricLog;
        long ratePerMin = elapsed > 0 ? ( received * 60000 / elapsed ) : 0;

        LOGGER.info( "AuthController Consumer Metrics - received={} processed={} failed={} downtime={} rate={}/min health={}", 
            received, processed, failed, downtime, ratePerMin, isHealthy ? "HEALTHY" : "UNHEALTHY" );

        vertx.eventBus().publish( METRICS_BUS_ADDR, new JsonObject()
            .put( "messagesReceived", received )
            .put( "messagesProcessed", processed )
            .put( "messagesFailed", failed )
            .put( "downtimeEvents", downtime )
            .put( "isHealthy", isHealthy )
            .put( "lastDowntimeReason", lastDowntimeReason )
            .put( "timestamp", now ) );

        lastMetricLog = now;
      }
    } );
  }

  private void startHealthTimer()
  {
    vertx.setPeriodic( 30000, id -> {
      try
      {
        if( natsTlsClient.isHealthy() )
        {
          if( !isHealthy )
            markHealthy( "Health check recovered" );
        }
        else
        {
          if( isHealthy )
            recordDowntime( "NATS connection unhealthy" );
        }
      }
      catch( Exception e )
      {
        if( isHealthy )
          recordDowntime( "Health check error: " + e.getMessage() );
      }
    } );
  }

  private void recordDowntime( String reason )
  {
    if( isHealthy )
    {
      isHealthy = false;
      lastDowntimeStart = System.currentTimeMillis();
      lastDowntimeReason = reason;
      downtimeEvents.incrementAndGet();
      LOGGER.warn( "Consumer downtime started reason={}", reason );
      vertx.eventBus().publish( DOWNTIME_START_BUS_ADDR, new JsonObject()
          .put( "reason", reason )
          .put( "timestamp", lastDowntimeStart )
          .put( "serviceId", "authcontroller" )
          .put( "component", "consumer" ) );
    }
  }

  private void markHealthy( String reason )
  {
    if( !isHealthy )
    {
      long duration = System.currentTimeMillis() - lastDowntimeStart;
      isHealthy = true;
      LOGGER.info( "Consumer service recovered downtimeMs={} reason={}", duration, reason );
      vertx.eventBus().publish( DOWNTIME_END_BUS_ADDR, new JsonObject()
          .put( "recoveryReason", reason )
          .put( "downtimeDuration", duration )
          .put( "timestamp", System.currentTimeMillis() )
          .put( "serviceId", "authcontroller" )
          .put( "component", "consumer" ) );
      lastDowntimeReason = null;
    }
  }

  // -------- Cleanup --------
  private void cleanup()
  {
    LOGGER.info( "AuthControllerConsumerVert.cleanup - start" );
    try
    {
      if( requestSubscription != null )
      {
        try
        {
          if (requestSubscription instanceof Subscription && requestSubscription instanceof io.nats.client.JetStreamSubscription)
          {
            try { ((io.nats.client.JetStreamSubscription)requestSubscription).drain(java.time.Duration.ofSeconds(2)); } catch (Exception ignore) {}
          }
        } catch (Throwable ignored) {}
        try { requestSubscription.unsubscribe(); } catch (Exception e) { LOGGER.debug( "Unsubscribe error: {}", e.getMessage() ); }
        requestSubscription = null;
      }
      
      if( workerExecutor != null )
      {
        workerExecutor.close();
      }
    }
    catch( Exception e )
    {
      LOGGER.warn( "Cleanup partial failure: {}", e.getMessage() );
    }
    LOGGER.info( "AuthControllerConsumerVert.cleanup - complete" );
  }
  
  // Metrics getters
  public long getMessagesReceived()   { return messagesReceived.get(); }
  public long getMessagesProcessed()  { return messagesProcessed.get(); }
  public long getMessagesFailed()     { return messagesFailed.get(); }
  public long getDowntimeEvents()     { return downtimeEvents.get(); }
  public boolean isHealthy()          { return isHealthy; }
  public String getLastDowntimeReason(){ return lastDowntimeReason; }
  public long getMessageReceiptCounter() { return messageReceiptCounter.get(); }
}