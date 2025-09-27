package verticle;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.eventbus.EventBus;

import io.nats.client.*;
import io.nats.client.impl.Headers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.model.ServiceCoreIF;
import core.nats.NatsConsumerErrorHandler;
import core.nats.NatsTLSClient;

import java.util.Map;
import java.util.concurrent.TimeUnit;

public class MetadataClientConsumerVert extends AbstractVerticle
{
  private static final Logger LOGGER            = LoggerFactory.getLogger( MetadataClientConsumerVert.class );
  private static final String CONSUMER_NAME     = "metadata-request-consumer";

  private NatsTLSClient             natsTlsClient = null;
  private NatsConsumerErrorHandler  errHandler   = new NatsConsumerErrorHandler();
  
  private WorkerExecutor  workerExecutor = null;
  private Subscription    consumer       = null;

  public MetadataClientConsumerVert( NatsTLSClient natsTlsClient )
  {
    this.natsTlsClient = natsTlsClient;
  }

  
  @Override
  public void start( Promise<Void> startPromise )
  {
    workerExecutor  = vertx.createSharedWorkerExecutor("msg-handler");
    
    startRequestConsumer().onSuccess(result -> 
    {
      LOGGER.info("MetadataClientConsumerVert started successfully");
      startPromise.complete(); // Single completion point
    })
    .onFailure(throwable -> {
        String msg = "Failed to initialize MetadataClientConsumerVert: " + throwable.getMessage();
        LOGGER.error(msg, throwable);
        cleanup();
        startPromise.fail(msg); // Single failure point
    });
  }

  private MessageHandler createMessageHandler() 
  {
    return (msg) -> 
    {
      workerExecutor.executeBlocking(() -> 
      {
          try 
          {
            handleRequestMessage( msg );
            msg.ack();
            LOGGER.info( "Consumer - Message Received and Ack'd - " + new String( msg.getData() ));
            return "success";
          } 
          catch( Throwable t )
          {
            LOGGER.error( "Error processing message. Error = " + t.getMessage() );
            throw t;
          }
      }).onComplete(ar -> 
      {
        if( ar.failed() ) 
        {
          LOGGER.error("Worker execution failed: {}", ar.cause().getMessage());
          errHandler.handleMessageProcessingFailure( natsTlsClient.getNatsConnection(), consumer, msg, ar.cause());
        }
      });
    };
  };
 
  private Future<Void> startRequestConsumer() 
  {
    LOGGER.info("MetadataClientConsumerVert.startRequestConsumer() - Starting metadata request consumer");

    Promise<Void>    promise       = Promise.promise();
    MessageHandler   requestMsgHandler = createMessageHandler();
    String           subject       = ServiceCoreIF.MetaDataClientRequestStream; // Using JetStream subject naming
 
    // Use the consumer pool in NatsTLSClient
    natsTlsClient.getConsumerPoolManager()
      .getOrCreateConsumer(subject, CONSUMER_NAME, requestMsgHandler)
      .onSuccess( c -> 
       {
         this.consumer = c;
         LOGGER.info("Metadata request consumer created and subscribed to subject: {}", subject);
         promise.complete();
       })
      .onFailure( e -> 
       {
         LOGGER.error("Consumer creation exception. Error = - " + e.getMessage());
         cleanup();
         promise.fail(e);
       });
    
    return promise.future();
  }

  private void handleRequestMessage( Message msg )
  {
    try
    {
      // For NATS, headers are accessed differently
      Headers headers = msg.getHeaders();
      String eventType = null;
      
      if (headers != null)
      {
        eventType = headers.getFirst( ServiceCoreIF.MsgHeaderEventType );
      }
      
      EventBus eventBus = vertx.eventBus();

      switch( eventType != null ? eventType : "unknown" )
      {
        case "cert-notify":
        { 
          String jsonStr = processSave( msg );
          Future<io.vertx.core.eventbus.Message<byte[]>> response = eventBus.request( "nats.cert.notify", jsonStr.getBytes() );
          response.onComplete( this::handleResponse );
          break;
        }
        case "save":
        { 
          String jsonStr = processSave( msg );
          Future<io.vertx.core.eventbus.Message<byte[]>> response = eventBus.request( "cassandra.save", jsonStr.getBytes() );
          response.onComplete( this::handleResponse );
          break;
        }
        case "get":
        {
          String jsonStr = processGet( msg );
          Future<io.vertx.core.eventbus.Message<byte[]>> response = eventBus.request( "cassandra.get", jsonStr.getBytes() );
          response.onComplete( this::handleResponse );
          break;
        }
        case "getAll":
        {
          String jsonStr = processGetAll( msg );
          Future<io.vertx.core.eventbus.Message<byte[]>> response = eventBus.request( "cassandra.get", jsonStr.getBytes() );
          response.onComplete( this::handleResponse );
          break;
        }
        case "update":
        {
          String jsonStr = processUpdate( msg );
          Future<io.vertx.core.eventbus.Message<byte[]>> response = eventBus.request( "cassandra.update", jsonStr.getBytes() );
          response.onComplete( this::handleResponse );
          break;
        }
        case "delete":
        {
          String jsonStr = processDelete( msg );
          Future<io.vertx.core.eventbus.Message<byte[]>> response = eventBus.request( "cassandra.delete", jsonStr.getBytes() );
          response.onComplete( this::handleResponse );
          break;
        }
        default:
        {
          LOGGER.warn( "Unknown eventType: {}", eventType );
          break;
        }
      }
    }
    catch( Exception e )
    {
      LOGGER.error( "Error processing NATS message", e );
      throw new RuntimeException("Error processing message", e);
    }
  }
  
  private String handleResponse( AsyncResult<io.vertx.core.eventbus.Message<byte[]>> ar )
  {
    if( ar.succeeded() ) { return ServiceCoreIF.SUCCESS; }
     else { return( ServiceCoreIF.FAILURE + " Error: " + ar.cause() ); }
  }

   
  private String processSave( Message msg )
  {
    // Implementation depends on your message structure
    return null;
  }
  
  private String processGet( Message msg )
  {
    // Implementation depends on your message structure
    return null;
  }

  private String processGetAll( Message msg )
  {
    // Implementation depends on your message structure
    return null;
  }

  private String processUpdate( Message msg )
  {
    // Implementation depends on your message structure
    return null;
  }

  private String processDelete( Message msg )
  {
    // Implementation depends on your message structure
    return null;
  }
  
  @Override
  public void stop( Promise<Void> stopPromise ) 
  {
    try 
    {
      cleanup();
      LOGGER.info("NATS client closed");
      stopPromise.complete();
    } 
    catch( Exception e )
    {
      LOGGER.error("Error closing NATS client", e);
      stopPromise.fail( e );
    }
  }
 
  private void cleanup() 
  {
    // Close worker executor
    if( workerExecutor != null ) 
    {
      try 
      {
        workerExecutor.close();
        LOGGER.info("Closed worker executor");
      }
      catch( Exception e ) 
      {
        LOGGER.warn("Error while closing worker executor: " + e.getMessage(), e);
      }
    }
    
    // Close consumer
    if( consumer != null ) 
    {
      try 
      {
        if (consumer.isActive())
        {
          consumer.unsubscribe();
        }
        LOGGER.info("Closed consumer");
      }
      catch( Exception e ) 
      {
        LOGGER.warn("Error closing consumer: " + e.getMessage(), e);
      }
    }
    
    LOGGER.info("MetadataClientConsumerVert cleanup completed");
  }  
}
