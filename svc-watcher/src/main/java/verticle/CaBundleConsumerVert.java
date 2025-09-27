package verticle;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.KeySecretManager;
import core.model.ServiceCoreIF;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.json.JsonObject;

import io.nats.client.JetStreamSubscription;
import io.nats.client.MessageHandler;

import core.nats.NatsTLSClient;
import core.nats.NatsConsumerErrorHandler;
import processor.CaBundleMsgProcessor;
import utils.WatcherConfig;

/**
 * NATS JetStream Consumer Verticle for CA Bundle Updates
 * 
 * Replaces the Pulsar-based consumer with NATS JetStream for CA bundle rotation messages.
 * Maintains the same message processing logic but uses NATS JetStream subscriptions.
 */
public class CaBundleConsumerVert extends AbstractVerticle
{
  private static final Logger LOGGER           = LoggerFactory.getLogger(CaBundleConsumerVert.class);
//  private static final String KEY_SUBSCRIPTION = "watcher-key-response";
  private static final String ServiceId        = "watcher";
  
  private KubernetesClient kubeClient       = null;
  private WatcherConfig    config           = null;
  private NatsTLSClient    natsTlsClient    = null;
  private KeySecretManager keyCache         = null;
  
  private String           nameSpace        = null;
  private WorkerExecutor   workerExecutor   = null;
  private JetStreamSubscription caSubscription = null;
  
  private NatsConsumerErrorHandler errHandler = null;

  public CaBundleConsumerVert( KubernetesClient kubeClient, NatsTLSClient natsTlsClient, KeySecretManager keyCache, WatcherConfig config, String nameSpace )
  {
    this.kubeClient     = kubeClient;
    this.natsTlsClient  = natsTlsClient;
    this.keyCache       = keyCache;
    this.config         = config;
    this.nameSpace      = nameSpace;
    this.errHandler     = new NatsConsumerErrorHandler();
  }
  
  @Override
  public void start( Promise<Void> startPromise ) 
   throws Exception
  {
    LOGGER.info("CaBundleConsumerVert.start() - Starting CaBundleConsumerVert");
    workerExecutor = vertx.createSharedWorkerExecutor("msg-handler");
    
    try 
    {
      startCAConsumer();
      
      startPromise.complete();
      LOGGER.info("CaBundleConsumerVert started successfully");
    }
    catch( Exception e ) 
    {
      LOGGER.error("Error starting CaBundleConsumerVert: {}", e.getMessage(), e);
      cleanup();
      startPromise.fail(e);
    }
  }  

  @Override
  public void stop(Promise<Void> stopPromise) 
   throws Exception
  {
    LOGGER.info("Stopping CaBundleConsumerVert");
    cleanup();
    stopPromise.complete();
    LOGGER.info("CaBundleConsumerVert stopped successfully");
  }

  private void closeSubscription() 
  {
    if( caSubscription != null ) 
    {
      try 
      {
        caSubscription.unsubscribe();
        LOGGER.info("CA bundle subscription closed");
      } 
      catch( Exception e ) 
      {
        LOGGER.warn("Error closing CA bundle subscription: {}", e.getMessage(), e);
      }
      caSubscription = null;
    }
  }

  private void closeWorkerExecutor() 
  {
    if( workerExecutor != null ) 
    {
      try 
      {
        workerExecutor.close();
        LOGGER.info("Worker executor closed");
      } 
      catch( Exception e ) 
      {
        LOGGER.warn("Error closing worker executor: {}", e.getMessage(), e);
      }
      workerExecutor = null;
    }
  }

  private void cleanup()
  {
    closeSubscription();
    closeWorkerExecutor();
    
    LOGGER.info("CaBundleConsumerVert cleanup completed");
  }
  
  /**
   * Use the NatsTLSClient's consumer pool to start the CA bundle consumer.
   * This method creates a NATS JetStream subscription for CA bundle rotation messages.
   */
  private Future<Void> startCAConsumer()
  {
    LOGGER.info("CaBundleConsumerVert.startCAConsumer() - Starting CA Bundle rotate consumer via NATS JetStream" );

    String subscriptionName = ServiceId + "-ca-update-" + UUID.randomUUID().toString();
    MessageHandler caMsgHandler = createCAMessageHandler();

    // Use the consumer pool manager from NatsTLSClient
    return natsTlsClient.getConsumerPoolManager()
      .getOrCreateConsumer( ServiceCoreIF.MetaDataClientCaCertStream, subscriptionName, caMsgHandler )
      .compose((subscription) ->
       {
         this.caSubscription = (JetStreamSubscription) subscription;
         LOGGER.info("CA Bundle consumer started successfully");
         return Future.succeededFuture((Void) null );
       })
      .onComplete( ar -> 
       {
         if( ar.failed() ) 
         {
           LOGGER.error("CA Bundle consumer creation failed: {}", ar.cause().getMessage());
           closeSubscription();
         }
       });
  }
 
  /**
   * Message handler for CA bundle rotation messages
   * This replaces the Pulsar MessageListener with NATS MessageHandler
   */
  private MessageHandler createCAMessageHandler() 
  {
    return (msg) -> 
    {
      workerExecutor.executeBlocking(() -> 
      {
        LOGGER.info( "=======================================================================================");
        LOGGER.info( "CaBundleConsumerVert.createCAMessageHandler received CABundle msg.");
        LOGGER.info( "=======================================================================================");
    
        try 
        {
          byte[] msgBytes = msg.getData();
 
          CaBundleMsgProcessor processor = new CaBundleMsgProcessor( vertx, workerExecutor, kubeClient, natsTlsClient, keyCache  );

          // Acknowledge the message now - NATS JetStream acknowledgments
          // are handled automatically or manually based on consumer configuration
          msg.ack();
 
          processor.processMsg( msgBytes );
          
          return ServiceCoreIF.SUCCESS;
        } 
        catch( Throwable t ) 
        {
          LOGGER.error("Error processing CA bundle message: {}", t.getMessage(), t);
          
          if( errHandler.isUnrecoverableError(t) ) 
          {
            LOGGER.error("Unrecoverable error detected. Deploying recovery procedure.");
            initiateRecovery();
          }
          
          // NATS JetStream - negative acknowledge on error
          try {
            msg.nak();
          } catch (Exception e) {
            LOGGER.warn("Failed to NAK message: {}", e.getMessage());
          }
          
          throw t;
        }
      }).onComplete(ar -> 
        {
          if( ar.failed() ) 
          {
            LOGGER.error("Worker execution failed: {}", ar.cause().getMessage());
            errHandler.handleMessageProcessingFailure( natsTlsClient.getNatsConnection(), caSubscription, msg, ar.cause());
          }
        });
    };
  }
  
  /**
   * Initiates recovery procedure when unrecoverable errors are detected
   */
  private void initiateRecovery() 
  {
    LOGGER.info("CaBundleConsumerVert.initiateRecovery() - Initiating verticle recovery process");
    
    // Deploy a new instance of this verticle before undeploying the current one
    String verticleID = deploymentID();

    DeploymentOptions options = new DeploymentOptions();
    options.setConfig( new JsonObject().put( "worker", true ) );

    CaBundleConsumerVert newVert = new CaBundleConsumerVert( kubeClient, natsTlsClient, keyCache, config, nameSpace);
    
    vertx.deployVerticle( newVert, options ).onComplete(ar -> 
    {
      if( ar.succeeded() )
      {
        String newDeploymentId = ar.result();
        LOGGER.info("CaBundleConsumerVert.initiateRecovery() - Deployed replacement CaBundleConsumerVert verticle: {}", newDeploymentId);
        
        // Undeploy this verticle after successful deployment of the replacement
        vertx.undeploy( verticleID ).onComplete(ur -> 
        {
          if( ur.succeeded() ) 
          {
            LOGGER.info("CaBundleConsumerVert.initiateRecovery() - Current verticle undeployed successfully");
          } 
          else 
          {
            LOGGER.error("CaBundleConsumerVert.initiateRecovery() - Failed to undeploy current verticle: {}", ur.cause().getMessage());
          }
        });
      } 
      else 
      {
        LOGGER.error("CaBundleConsumerVert.initiateRecovery() - Failed to deploy replacement verticle: {}", ar.cause().getMessage());
      }
    });
  }
}