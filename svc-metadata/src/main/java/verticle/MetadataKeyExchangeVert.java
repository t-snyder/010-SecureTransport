package verticle;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import core.crypto.KyberKEMCrypto;
import core.handler.KeySecretManager;
import core.model.KyberExchangeMessage;
import core.model.ServiceBundle;
import core.model.ServiceCoreIF;
import core.model.SharedSecretInfo;
import core.processor.SignedMessageProcessor;
import core.nats.NatsConsumerErrorHandler;
import core.nats.NatsTLSClient;
import core.transport.SignedMessage;
import core.model.DilithiumKey;

import io.nats.client.Subscription;
import io.nats.client.Message;
import io.nats.client.MessageHandler;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Metadata service processing for a key exchange request which will return the kyber key exchange
 * as well as a ServiceBundle encrypted with the new shared key.
 * 
 */
public class MetadataKeyExchangeVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger(MetadataKeyExchangeVert.class);
  
  private final NatsTLSClient    natsTlsClient;
  private final KeySecretManager keyCache;
    
  private final String serviceId = "metadata";
  
  private WorkerExecutor            workerExecutor;
  private NatsConsumerErrorHandler  errHandler  = new NatsConsumerErrorHandler();
  private Subscription              keyConsumer = null;
  private SignedMessageProcessor    signedMessageProcessor;
    
  //Request queuing for startup coordination
  private final AtomicBoolean          metadataServiceReady = new AtomicBoolean(false);
  private final Queue<Message> queuedRequests       = new ConcurrentLinkedQueue<>();

  private static final int MAX_QUEUED_REQUESTS = 100; // Prevent memory issues
  
  public MetadataKeyExchangeVert( NatsTLSClient natsTlsClient, KeySecretManager  keyCache )
  {
    this.natsTlsClient            = natsTlsClient;
    this.keyCache                 = keyCache;
  }

  @Override
  public void start( Promise<Void> startPromise )
  {
    try
    {
      workerExecutor         = vertx.createSharedWorkerExecutor( "metadata-key-exch", 2, 360000 );
      signedMessageProcessor = new SignedMessageProcessor(workerExecutor, keyCache);

      // Listen for metadata service readiness
      setupMetadataReadinessListener();
         
      startKeyExchConsumer()
        .onSuccess( res -> 
         {
           startPromise.complete();
           LOGGER.info( "Metadata Key Exchange Vert started successfully" );
         })
        .onFailure( e -> 
        {
          LOGGER.error( "Failed to start KeyExchange consumer: {}", e.getMessage(), e );
          startPromise.fail( e );
        });
    } 
    catch( Exception e )
    {
      LOGGER.error( "Failed to start MetadataKeyExchangeVert: {}", e.getMessage(), e );
      startPromise.fail( e );
    }
  }
  
  /**
   * Setup listener for metadata service readiness notification
   */
  private void setupMetadataReadinessListener()
  {
    LOGGER.info("Setting up metadata service readiness listener");
    
    vertx.eventBus().consumer("metadata.service.ready", msg -> 
    {
      String readyServiceId = (String) msg.body();
      
      if( "metadata".equals( readyServiceId ))
      {
        LOGGER.info("Received metadata service ready notification - processing queued requests");
        
        // Mark as ready
        metadataServiceReady.set( true );
        
        // Process any queued requests
        processQueuedRequests();
      } 
      else 
      {
        LOGGER.debug("Received ready notification for service: {} (ignoring)", readyServiceId );
      }
    });
  }  

  /**
   * Process any requests that were queued while waiting for metadata service readiness
   */
  private void processQueuedRequests()
  {
    if( queuedRequests.isEmpty() ) 
    {
      LOGGER.info("No queued key exchange requests to process");
      return;
    }

    int processedCount = 0;
    Message queuedMessage;
    
    while(( queuedMessage = queuedRequests.poll() ) != null ) 
    {
      Message msg          = queuedMessage; // Final variable for lambda
      final int       currentCount = processedCount; // Capture value for lambda
      
      workerExecutor.executeBlocking( () -> 
      {
        try 
        {
          LOGGER.info("Processing queued key exchange request #{}", currentCount + 1);
          handleKeyExchangeMsg(msg);
          msg.ack();
          LOGGER.info("Successfully processed queued key exchange request");
          return ServiceCoreIF.SUCCESS;
        } 
        catch (Throwable t) 
        {
          LOGGER.error("Error processing queued key exchange request: {}", t.getMessage(), t);
          
          if( errHandler.isUnrecoverableError(t) ) 
          {
            LOGGER.error("Unrecoverable error detected. Deploying recovery procedure.");
            initiateRecovery();
          }
          throw t;
        }
      }).onComplete(ar -> 
        {
          if (ar.failed()) {
            LOGGER.error("Worker execution failed for queued request: {}", ar.cause().getMessage());
            errHandler.handleMessageProcessingFailure(natsTlsClient.getNatsConnection(), keyConsumer, msg, ar.cause());
          }
        });
      
      processedCount++;
    }
    
    LOGGER.info("Finished processing {} queued key exchange requests", processedCount);
  }
  
  public Future<ServiceBundle> getCurrentServiceBundle( String serviceId ) {
    return vertx.eventBus().<Buffer>request( ServicesACLWatcherVert.SERVICE_BUNDLE_REQUEST_ADDR,
                                             serviceId
                                           )
                           .compose( msg -> 
                            {
                              try 
                              {
                                ServiceBundle bundle = ServiceBundle.deSerialize(msg.body().getBytes());
                                return Future.succeededFuture(bundle);
                              } 
                              catch( Exception e ) 
                              {
                                return Future.failedFuture(e);
                              }
    });
  }
  
  @Override
  public void stop()
   throws Exception
  {
    LOGGER.info( "Stopping Metadata Key Exchange Vert" );

    // Clear any remaining queued requests
    int remainingRequests = queuedRequests.size();
    if( remainingRequests > 0 ) 
    {
      LOGGER.warn("Discarding {} remaining queued requests on shutdown", remainingRequests);
      queuedRequests.clear();
    }
    
    if( workerExecutor != null ) workerExecutor.close();
    if( keyConsumer != null && keyConsumer.isActive() ) keyConsumer.unsubscribe();

    LOGGER.info( "Metadata Key Exchange Vert stopped" );
  }
   
  /**
   * Message handler for key exchange responses
   */
  private MessageHandler createKeyExchangeMessageHandler() 
  {
    return (msg) -> 
    {
      // Check if metadata service is ready
      if( !metadataServiceReady.get() ) 
      {
        LOGGER.info("Metadata service not ready - queuing key exchange request");
        
        // Check queue size limit
        if( queuedRequests.size() >= MAX_QUEUED_REQUESTS ) 
        {
          LOGGER.error("Request queue full ({} requests) - rejecting new request", MAX_QUEUED_REQUESTS);
          msg.nak();
          return;
        }
        
        // Queue the request
        queuedRequests.offer(msg);
        LOGGER.info("Queued key exchange request (queue size: {})", queuedRequests.size());
        return;
      }
      
      workerExecutor.executeBlocking(() -> 
      {
        try 
        {
          handleKeyExchangeMsg( msg );
          msg.ack();
          LOGGER.info( "keyConsumer - Message Received and Ack'd - " );
          return ServiceCoreIF.SUCCESS;
        } 
        catch( Throwable t ) 
        {
          LOGGER.error("Error processing key exchange response: {}", t.getMessage(), t);
          
          if( errHandler.isUnrecoverableError(t) ) 
          {
            LOGGER.error("Unrecoverable error detected. Deploying recovery procedure.");
            initiateRecovery();
          }
          throw t;
        }
      }).onComplete(ar -> 
        {
          if( ar.failed() ) 
          {
            LOGGER.error("Worker execution failed: {}", ar.cause().getMessage());
            errHandler.handleMessageProcessingFailure( natsTlsClient.getNatsConnection(), keyConsumer, msg, ar.cause());
          }
        });
    };
  }

 
  private Future<Void> startKeyExchConsumer()
  {
    LOGGER.info("MetadataKeyExchangeVert.startKeyExchConsumer() - Starting key exchange consumer");
    Promise<Void> promise = Promise.promise();
    MessageHandler keyMsgHandler = createKeyExchangeMessageHandler();
    String subject = ServiceCoreIF.KeyExchangeStreamBase + serviceId;  // Updated for JetStream naming

    // Use the pooled consumer from NatsTLSClient
    natsTlsClient.getConsumerPoolManager()
      .getOrCreateConsumer(subject, serviceId + "-key-exch-consumer", keyMsgHandler)
      .onSuccess( consumer -> 
       {
         this.keyConsumer = consumer;
         LOGGER.info("Key exchange consumer pooled and subscribed to subject: {}", subject );
         promise.complete();
       })
      .onFailure( e -> 
       {
         LOGGER.error("Consumer creation exception. Error = - " + e.getMessage());
         promise.fail(e);
       });

    return promise.future();
  }


  private void handleKeyExchangeMsg( Message msg ) 
   throws Exception
  {
    LOGGER.info( "========================================================================" );
    LOGGER.info( "MetadataKeyExchangeVert.handleKeyExchangeMsg received msg." );

    KyberExchangeMessage kyberMsg = KyberExchangeMessage.deSerialize( msg.getData() );
    if( kyberMsg == null )
    {
      String errMsg = "KeyExchangeVert.handleKeyExchangeMsg Could not deserialize msg.";
      LOGGER.error( errMsg );
      throw new RuntimeException( errMsg );
    }

    String eventType = kyberMsg.getEventType();
    if( eventType == null && msg.getHeaders() != null)
    {
      eventType = msg.getHeaders().getFirst( ServiceCoreIF.MsgHeaderEventType );
    }
 
    LOGGER.info( "KeyExchangeVert.handleKeyExchangeMsg eventType received is " + eventType );

    if( eventType == null )
    {
      String errMsg = "Message event type not found.";
      LOGGER.error( errMsg );
      throw new RuntimeException( errMsg );
    }
    
    if( eventType.compareTo( ServiceCoreIF.KyberKeyRequest    ) == 0  ||
        eventType.compareTo( ServiceCoreIF.KyberRotateRequest ) == 0 )
    {
      processKeyExchRequest( kyberMsg );
      return;
    }

    String errMsg = "Message was not a key request or rotation.";
    LOGGER.error( errMsg );
    throw new RuntimeException( errMsg );
  }
  

  /**
   * Handles a Kyber key exchange request and responds with a KyberExchangeMessage including the
   * encrypted ServiceBundle for the requesting service.
   */
  protected void processKeyExchRequest( KyberExchangeMessage kyberMsg ) 
   throws Exception 
  {
    LOGGER.info("Metadata service processing key exchange request from: {}", kyberMsg.getSourceSvcId());
   
    // Standard Kyber key exchange processing
    PublicKey                  publicKey     = KyberKEMCrypto.decodePublicKey( kyberMsg.getPublicKey() );
    SecretKeyWithEncapsulation encapsulation = KyberKEMCrypto.processKyberExchangeRequest( KyberKEMCrypto.encodePublicKey(publicKey));
    SharedSecretInfo           keyInfo       = SharedSecretInfo.buildSharedSecret( kyberMsg, publicKey, encapsulation.getEncoded());
   
    String responseType = kyberMsg.getEventType().compareTo( ServiceCoreIF.KyberKeyRequest) == 0 
                                                             ? ServiceCoreIF.KyberKeyResponse 
                                                             : ServiceCoreIF.KyberRotateResponse;

    // Create base response
    KyberExchangeMessage responseMsg = new KyberExchangeMessage( kyberMsg.getSecretKeyId(),
                                                                 serviceId, 
                                                                 kyberMsg.getSourceSvcId(),
                                                                 responseType, 
                                                                 kyberMsg.getPublicKey(), 
                                                                 encapsulation.getEncapsulation(),
                                                                 kyberMsg.getCreateTime(),
                                                                 kyberMsg.getExpiryTime()
                                                               );

    // Process the complete service bundle generation
    generateSignedMessage( kyberMsg.getSourceSvcId(), keyInfo )
      .onSuccess( signedMsg -> 
       {
         try
         {
           LOGGER.info("=======================================================================");
           LOGGER.info("Created Signed Message containing Service Bundle" );
           LOGGER.info( "Message Type   = " + signedMsg.getMessageType() );
           LOGGER.info( "Payload length = " + signedMsg.getPayload().length );
           
           responseMsg.setAdditionalData( SignedMessage.serialize( signedMsg ) );
           LOGGER.info("Successfully processed complete key exchange request for: {}", kyberMsg.getSourceSvcId());
        
           // Send response with encrypted ServiceBundle
           sendKeyExchangeMessage( kyberMsg.getSourceSvcId(), responseMsg);
           keyCache.putEncyptionSharedSecret( keyInfo );
         }
         catch( Exception e )
         {
           String errMsg = "Error sending KyberMsg response. Error = " + e.getMessage();
           LOGGER.error( errMsg );
           throw new RuntimeException( errMsg );
         }
       })
      .onFailure( err -> 
       {
         LOGGER.error( "Failed to process complete key exchange for {}: {}", 
                        kyberMsg.getSourceSvcId(), err.getMessage(), err);
          
         // Send response without ServiceBundle as fallback
         sendKeyExchangeMessage( kyberMsg.getSourceSvcId(), responseMsg);
         keyCache.putEncyptionSharedSecret( keyInfo );
       });
  }

  /**
   * Generate SignedMessage for the requesting service with topic permissions and keys
   * Updated to use shared secret encryption instead of topic key encryption.
   */
  private Future<SignedMessage> generateSignedMessage(String targetServiceId, SharedSecretInfo sharedSecret) 
  {
    LOGGER.info("Generating ServiceBundle for service: {}", targetServiceId);

    // Get the bundle (returns Future<ServiceBundle>)
    return getCurrentServiceBundle(targetServiceId)
        .compose(( ServiceBundle bundle ) -> 
            // Serialize (blocking)
            workerExecutor.executeBlocking(() -> 
            {
              byte[] serializedBundle = ServiceBundle.serialize(bundle);
              if (serializedBundle == null || serializedBundle.length == 0) 
              {
                throw new RuntimeException("Failed to serialize ServiceBundle for service: " + targetServiceId);
              }
              return serializedBundle;
            })
         )
        .compose(( byte[] serializedBundle) ->
        {
          String subject = ServiceCoreIF.KeyExchangeStreamBase + targetServiceId;  // Updated for JetStream
          // Use the new overloaded method that accepts shared secret
          return signedMessageProcessor.createSignedMessage(
              targetServiceId,                    // serviceId
              serializedBundle,                   // serialized ServiceBundle
              "ServiceBundle",                    // messageType
              "ServiceBundle",                    // payloadType
              subject,                            // subject (was topic)
              sharedSecret.getSharedSecret()      // sharedSecret for encryption
          );
         })
        .onFailure(err -> 
        {
            LOGGER.error("Failed to process ServiceBundle for service: {}", targetServiceId, err);
        });
  }
  
  private void sendKeyExchangeMessage( String targetServiceId, KyberExchangeMessage responseMsg )
  {
    LOGGER.info("Sending key exchange response to service: {}", targetServiceId);

    try 
    {
      byte[] responseBytes = KyberExchangeMessage.serialize( responseMsg );
      if( responseBytes == null || responseBytes.length == 0 ) 
      {
        LOGGER.warn("Failed to serialize KyberExchangeMessage for response to {}", targetServiceId);
        return;
      }
      
      String subject = ServiceCoreIF.KeyExchangeStreamBase + targetServiceId;  // Updated for JetStream
 
      natsTlsClient.publish( subject, responseBytes )
        .onSuccess(v -> LOGGER.info("Sent KyberExchangeMessage to subject: {}", subject))
        .onFailure(e -> LOGGER.error("Failed to send KyberExchangeMessage to {}: {}", subject, e.getMessage(), e));
    } 
    catch( Exception e ) 
    {
      LOGGER.error("Error serializing or sending KyberExchangeMessage for response: {}", e.getMessage(), e);
    }
  }
  
  /**
   * Initiates recovery procedure when unrecoverable errors are detected
   */
  private void initiateRecovery() 
  {
    LOGGER.info("Initiating verticle recovery process");
    
    // Deploy a new instance of this verticle before undeploying the current one
    String verticleID = deploymentID();

    DeploymentOptions natsOptions = new DeploymentOptions();
    natsOptions.setConfig( new JsonObject().put( "worker", true ) );

    MetadataKeyExchangeVert cVert  = new MetadataKeyExchangeVert( natsTlsClient, keyCache );
    Future<String>  result = vertx.deployVerticle( cVert, natsOptions );

    if( result.succeeded() )
    {
      LOGGER.info( "Deployed replacement MetadataKeyExchangeVert verticle: " + result.result() );
 
      Future<Void> undeployResult = vertx.undeploy( verticleID );
      if( undeployResult.succeeded() )
      {
        LOGGER.info("Current verticle undeployed successfully");
      } 
      else 
      {
        LOGGER.error( "Failed to undeploy MetadataKeyExchangeVert verticle. Error = " + undeployResult.cause() );
      }
    }
  }
}

