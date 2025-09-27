package core.verticle;

import io.nats.client.Message;
import io.nats.client.MessageHandler;
import io.nats.client.Subscription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.KeySecretManager;
import core.model.ServiceBundle;
import core.model.ServiceCoreIF;
import core.processor.SignedMessageProcessor;
import core.nats.NatsConsumerErrorHandler;
import core.nats.NatsTLSClient;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;

public class ServiceBundleVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger( ServiceBundleVert.class);

  // NATS components
  private Subscription bundleSubscription = null;
  private NatsConsumerErrorHandler errHandler = new NatsConsumerErrorHandler();

  private NatsTLSClient natsTlsClient;
  private KeySecretManager keyCache;
  private WorkerExecutor workerExecutor;
  private SignedMessageProcessor signedMsgProcessor;

  private String serviceId;
  private String consumerSubjectId;

  public ServiceBundleVert( NatsTLSClient natsTlsClient, KeySecretManager keyCache, 
                            String serviceId, String consumerSubjectId)
  {
    this.natsTlsClient = natsTlsClient;
    this.keyCache = keyCache;
    this.serviceId = serviceId;
    this.consumerSubjectId = consumerSubjectId;
  }

  @Override
  public void start(Promise<Void> startPromise)
  {
    this.workerExecutor = vertx.createSharedWorkerExecutor("bundle-handler-" + serviceId, 2);
    this.signedMsgProcessor = new SignedMessageProcessor(workerExecutor, keyCache);

    LOGGER.info("NatsServiceBundleVert initializing for service: {}", serviceId);
  
    // Initialization in worker thread to avoid blocking event loop
    workerExecutor.executeBlocking(()-> 
    {
      try
      {
        startServiceBundleConsumer();
        LOGGER.info("NatsServiceBundleVert initialized successfully for service: {}", serviceId);
      } 
      catch (Exception e)
      {
        LOGGER.error("Failed to initialize NatsServiceBundleVert for service: {}", serviceId, e);
        startPromise.fail(e);
      }

      return ServiceCoreIF.SUCCESS;
    }).onSuccess(v -> startPromise.complete())
       .onFailure(startPromise::fail);
  }

  @Override
  public void stop(Promise<Void> stopPromise)
  {
    LOGGER.info("Stopping NatsServiceBundleVert for service: {}", serviceId);
    cleanup();
    stopPromise.complete();
  }

  private void cleanup()
  {
    try
    {
      if (workerExecutor != null)
      {
        workerExecutor.close();
      }
      
      if (bundleSubscription != null && bundleSubscription.isActive())
      {
        bundleSubscription.unsubscribe();
      }
      
      LOGGER.info("NatsServiceBundleVert cleaned up for service: {}", serviceId);
    } 
    catch (Exception e)
    {
      LOGGER.error("Error during cleanup: {}", e.getMessage(), e);
    }
  }
 
  /**
   * Message handler for Service Bundles
   */
  private MessageHandler serviceBundleMsgHandler() 
  {
    return (msg) -> 
    {
      workerExecutor.executeBlocking(() -> 
      {
        try 
        {
          handleBundleMsg(msg);
          msg.ack();
          LOGGER.info("serviceBundleConsumer - Message Received and Ack'd");
          return ServiceCoreIF.SUCCESS;
        } 
        catch (Throwable t) 
        {
          LOGGER.error("Error processing service bundle message: {}", t.getMessage(), t);
          
          if (errHandler.isUnrecoverableError(t)) 
          {
            LOGGER.error("Unrecoverable error detected. Deploying recovery procedure.");
            // TODO: Add recovery procedure
          }
          throw t;
        }
      }).onComplete(ar -> 
        {
          if (ar.failed()) 
          {
            LOGGER.error("Worker execution failed: {}", ar.cause().getMessage());
            errHandler.handleMessageProcessingFailure(natsTlsClient.getNatsConnection(), msg, ar.cause());
          }
        });
    };
  }

  private void startServiceBundleConsumer() 
    throws Exception
  {
    LOGGER.info("NatsServiceBundleVert.startServiceBundleConsumer() - Starting service bundle push consumer");

    String subject = ServiceCoreIF.BundlePushStreamBase + consumerSubjectId;
    String consumerName = serviceId + "-bundle-push-consumer";
 
    natsTlsClient.getConsumerPoolManager()
      .getOrCreateConsumer(subject, consumerName, serviceBundleMsgHandler())
     .onSuccess(subscription -> 
      {
        this.bundleSubscription = subscription;
        LOGGER.info("NatsServiceBundleVert: Subscribed to Service Bundle Push subject: {}", subject);
      })
     .onFailure(ex -> 
      {
        LOGGER.error("Failed to subscribe to Service Bundle subject", ex);
      });
  }

  /**
   * The steps for receiving, decrypting and validating the message are essentially the reverse of creation:
   *   1) Deserialize the SignedMessage object
   *   2) Deserialize the EncryptedData into an Object.
   *   3) Obtain the shared secret key to decrypt using the serviceId and encryptKeyId
   *   4) Decrypt the payload using the EncryptedData and shared secret
   *   5) Obtain the signing public key using signerServiceId and signerKeyId
   *   6) Hash the payload bytes and verify the signing.
   *   7) Using the Message Type or Payload Type Deserialize the payload.
   * @param msg
   * @throws Exception
   */
  private void handleBundleMsg(Message msg) 
    throws Exception
  {
    LOGGER.info("========================================================================");
    LOGGER.info("NatsServiceBundleVert.handleBundleMsg received msg for subject: {}", msg.getSubject());

    // Decrypt, verify and obtain ServiceBundle bytes
    signedMsgProcessor.obtainDomainObject(msg.getData())
      .compose((byte[] requestBytes) -> 
      {
        // Deserialize ServiceBundle
        return workerExecutor.<ServiceBundle>executeBlocking(() -> {
          try 
          {
            return ServiceBundle.deSerialize(requestBytes);
          }
          catch (Exception e)
          {
            LOGGER.error("Error deserializing ServiceBundle: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to deserialize ServiceBundle", e);
          }
        });
      })
     .onSuccess(serviceBundle -> 
      {
        LOGGER.info("Successfully decrypted, deserialized, and verified ServiceBundle for serviceId={}", 
                   serviceBundle.getServiceId());
        // Apply the bundle (update keys, permissions, etc.)
        try 
        {
          keyCache.loadFromServiceBundle(serviceBundle);
          LOGGER.info("ServiceBundle loaded into keyCache successfully");
        }
        catch (Exception e)
        {
          LOGGER.error("Failed to load ServiceBundle into keyCache: {}", e.getMessage(), e);
        }
      })
    .onFailure(err -> 
     {
       LOGGER.error("Failed to decrypt/process/verify ServiceBundle", err);
     });
  }
}