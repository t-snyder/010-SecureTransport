package verticle;


import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.CertificateUpdateCallbackIF;
import core.handler.KeySecretManager;
import core.model.AuthenticationResponse;
import core.model.ServiceCoreIF;
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
import utils.GatekeeperConfig;

/**
 * GatekeeperConsumerVert (NATS): Consumes authentication responses on
 * configured subject and republishes them on the event bus for correlation
 * (gateway.response.received).
 */
public class GatekeeperConsumerVert extends AbstractVerticle implements CertificateUpdateCallbackIF
{

  private static final Logger LOGGER = LoggerFactory.getLogger( GatekeeperConsumerVert.class );
  private static final String CONSUMER_SUBSCRIPTION_PREFIX = "gateway-consumer-";

  private final NatsTLSClient natsTlsClient;
  private final GatekeeperConfig gatewayConfig;
  private final KeySecretManager keyCache;
  private final SignedMessageProcessor signedMsgProcessor;
  private final NatsConsumerErrorHandler errHandler = new NatsConsumerErrorHandler();

  private WorkerExecutor workerExecutor;
  private Subscription   responseSubscription;

  // Metrics
  private final AtomicLong messagesReceived = new AtomicLong();
  private final AtomicLong messagesProcessed = new AtomicLong();
  private final AtomicLong messagesFailed = new AtomicLong();
  private long lastMetricLog = System.currentTimeMillis();

  // Keep dynamic subscriptions if needed later
  private final Map<String, Subscription> subs = new ConcurrentHashMap<>();

  public GatekeeperConsumerVert( NatsTLSClient natsTlsClient, GatekeeperConfig gatewayConfig, KeySecretManager keyCache, SignedMessageProcessor signedMsgProcessor )
  {
    this.natsTlsClient = natsTlsClient;
    this.gatewayConfig = gatewayConfig;
    this.keyCache = keyCache;
    this.signedMsgProcessor = signedMsgProcessor;
  }

  @Override
  public void start( Promise<Void> startPromise )
  {
    LOGGER.info( "GatekeeperConsumerVert.start() - Starting (NATS)" );
    workerExecutor = vertx.createSharedWorkerExecutor( "gateway-consumer", 
                                                       8,      // poolSize
                                                       60_000, // maxExecuteTime in ms
                                                       TimeUnit.MILLISECONDS
                                                     );
    
    try
    {
      startConsumer();
      startMetricsReporting();
      natsTlsClient.addCertificateUpdateCallback( this );
      startPromise.complete();
      LOGGER.info( "GatekeeperConsumerVert started successfully" );
    }
    catch( Exception e )
    {
      LOGGER.error( "Error starting GatekeeperConsumerVert: {}", e.getMessage(), e );
      cleanup();
      startPromise.fail( e );
    }
  }

  @Override
  public void stop( Promise<Void> stopPromise )
  {
    LOGGER.info( "GatekeeperConsumerVert.stop() - Stopping" );
    cleanup();
    stopPromise.complete();
  }
  
  private void startConsumer()
  {
    String subject    = gatewayConfig.getGatekeeperResponseTopic();
    String queueGroup = CONSUMER_SUBSCRIPTION_PREFIX + "responses";

    workerExecutor.executeBlocking( () -> 
    {
      try
      {
        if( subs.containsKey( subject ) )
        {
          LOGGER.warn( "Consumer already exists for subject: {}", subject );
          return ServiceCoreIF.SUCCESS;
        }

        MessageHandler handler = msg -> {
          messagesReceived.incrementAndGet();
          handleAuthResponse( msg );
        };

        // Acquire subscription via attachPushQueue (join admin-created queue)
        natsTlsClient.attachPushQueue(subject, queueGroup, handler).onComplete( ar -> 
        {
          if( ar.succeeded() )
          {
            responseSubscription = ar.result(); // no cast
            subs.put( subject, responseSubscription );
            LOGGER.info( "Subscribed to auth responses subject: {}", subject );
          }
          else
          {
            LOGGER.error( "Failed to create subscription for {}: {}", subject, ar.cause().getMessage() );
          }
        });

        return ServiceCoreIF.SUCCESS;
      }
      catch( Exception e )
      {
        LOGGER.error( "Failed to create consumer for subject {}", subject, e );
        throw new RuntimeException( e );
      }
    } );
  }
  
  private void handleAuthResponse( Message msg )
  {
    if( msg == null )
      return;
    try
    {
      processAuthResponse( msg.getData() ).onSuccess( v -> {
        ackQuiet( msg );
        messagesProcessed.incrementAndGet();
        // Forward onto event bus for HTTP correlation (similar to Pulsar
        // version)
        vertx.eventBus().publish( "gateway.response.received", new io.vertx.core.json.JsonObject().put( "messageKey", extractMessageKey( msg ) ).put( "messageBody", msg.getData() ).put( "properties", headersToJson( msg ) ).put( "messageId", "nats" ) // You
                                                                                                                                                                                                                                                          // can
                                                                                                                                                                                                                                                          // add
                                                                                                                                                                                                                                                          // custom
                                                                                                                                                                                                                                                          // id
                                                                                                                                                                                                                                                          // if
                                                                                                                                                                                                                                                          // needed
            .put( "publishTime", System.currentTimeMillis() ) );
      } ).onFailure( err -> {
        messagesFailed.incrementAndGet();
        LOGGER.error( "Error processing response message: {}", err.getMessage(), err );
        nakQuiet( msg );
        if( errHandler.isUnrecoverableError( err ) )
        {
          LOGGER.error( "Unrecoverable error detected (no automated recovery logic implemented)" );
        }
      } );
    }
    catch( Exception e )
    {
      messagesFailed.incrementAndGet();
      LOGGER.error( "Synchronous exception handling message: {}", e.getMessage(), e );
      nakQuiet( msg );
    }
  }

  private String extractMessageKey( Message msg )
  {
    try
    {
      Object raw = msg.getHeaders();
      if( raw instanceof Map<?, ?> )
      {
        @SuppressWarnings( "unchecked" )
        Map<String, java.util.List<String>> cast = (Map<String, java.util.List<String>>)raw;
        var vals = cast.get( "messageKey" );
        if( vals != null && !vals.isEmpty() )
        {
          String first = vals.get( 0 );
          if( first != null && !first.isBlank() )
            return first;
        }
      }
    }
    catch( Throwable ignore )
    {
      // Non-fatal - we'll return a generated key below.
    }
    // Fallback: generated key when no readable header is present
    return "nats-" + System.nanoTime();
  }
  
  private io.vertx.core.json.JsonObject headersToJson( Message msg )
  {
    JsonObject json = new JsonObject();
    try
    {
      Object raw = msg.getHeaders();
      if( raw instanceof Map<?, ?> )
      {
        @SuppressWarnings( "unchecked" )
        Map<String, List<String>> cast = (Map<String, List<String>>)raw;
        cast.forEach( ( k, v ) -> 
        {
          if( k == null )  return;
          if( v == null || v.isEmpty() ) json.put( k, "" );
          else if( v.size() == 1 )       json.put( k, v.get( 0 ) );
          else json.put( k, String.join( ",", v ) );
        } );
      }
    }
    catch( Throwable ignore )
    {
      // If we can't read headers as a Map, return empty JSON object.
    }
    return json;
  }
  
  private Future<Void> processAuthResponse( byte[] data )
  {
    return signedMsgProcessor.obtainDomainObject( data ).map( o -> (byte[])o ).compose( bytes -> workerExecutor.<AuthenticationResponse> executeBlocking( () -> AuthenticationResponse.deserialize( bytes ) ) ).mapEmpty();
  }

  private void ackQuiet( Message msg )
  {
    try
    {
      msg.ack();
    }
    catch( Throwable t )
    {
      LOGGER.debug( "Ack failed/ignored: {}", t.getMessage() );
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
      LOGGER.debug( "Nak failed/ignored: {}", t.getMessage() );
    }
  }

  private void startMetricsReporting()
  {
    vertx.setPeriodic( 60000, id -> {
      long now = System.currentTimeMillis();
      if( now - lastMetricLog >= 60000 )
      {
        long r = messagesReceived.get();
        long p = messagesProcessed.get();
        long f = messagesFailed.get();
        long elapsed = now - lastMetricLog;
        long rate = elapsed > 0 ? ( r * 60000 / elapsed ) : 0;

        LOGGER.info( "Gateway Consumer Metrics - received={} processed={} failed={} rate={}/min", r, p, f, rate );
        lastMetricLog = now;
      }
    } );
  }

  @Override
  public void onCertificateUpdated()
  {
    LOGGER.info( "Certificate updated - recreating consumer subscriptions (NATS)" );
    workerExecutor.executeBlocking( () -> {
      try
      {
        closeAllSubscriptions();
        Thread.sleep( 1000 );
        startConsumer();
        return ServiceCoreIF.SUCCESS;
      }
      catch( Exception e )
      {
        LOGGER.error( "Failed to re-subscribe after certificate update: {}", e.getMessage() );
        throw new RuntimeException( e );
      }
    } );
  }

  @Override
  public void onCertificateUpdateFailed( Exception error )
  {
    LOGGER.error( "Certificate update failed for Gateway consumer", error );
  }

  private void closeAllSubscriptions()
  {
    if( responseSubscription != null )
    {
      try
      {
        // drain only if JetStreamSubscription
        if( responseSubscription instanceof io.nats.client.JetStreamSubscription )
        {
          try { ((io.nats.client.JetStreamSubscription) responseSubscription).drain( Duration.ofSeconds(2)); } catch (Exception ignore) {}
        }
        responseSubscription.unsubscribe();
      }
      catch( Exception e )
      {
        LOGGER.warn( "Failed to unsubscribe responseSubscription: {}", e.getMessage(), e );
      }
      responseSubscription = null;
    }
    subs.values().forEach( sub -> {
      try
      {
        sub.unsubscribe();
      }
      catch( Exception e )
      {
        LOGGER.warn( "Error unsubscribing additional sub: {}", e.getMessage() );
      }
    } );
    subs.clear();
  }

  private void cleanup()
  {
    LOGGER.info( "GatewayConsumerVert.cleanup - start" );
    closeAllSubscriptions();
    if( workerExecutor != null )
    {
      try
      {
        workerExecutor.close();
      }
      catch( Exception e )
      {
        LOGGER.warn( "Error closing worker executor: {}", e.getMessage() );
      }
    }
    LOGGER.info( "GatewayConsumerVert.cleanup - complete" );
  }

}