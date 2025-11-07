package core.verticle;

import java.util.UUID;

import io.nats.client.Message;
import io.nats.client.MessageHandler;
//import io.nats.client.Subscription;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.CaSecretManager;
import core.handler.KeySecretManager;
import core.model.CaBundle;
import core.model.ServiceCoreIF;
import core.processor.SignedMessageProcessor;
import core.nats.NatsConsumerErrorHandler;
import core.nats.NatsTLSClient;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;

public class CABundleUpdateVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger( CABundleUpdateVert.class);

  // NATS components
  private NatsConsumerErrorHandler errHandler = new NatsConsumerErrorHandler();

  private NatsTLSClient natsTlsClient;
  private KeySecretManager keyCache;
  private CaSecretManager caSecretManager; 
  private WorkerExecutor workerExecutor;
  private SignedMessageProcessor signedMsgProcessor;
 
  // Kubernetes integration
  private KubernetesClient kubeClient;
  
  private String serviceId;
  private String namespace;
  private String consumerSubjectId = ServiceCoreIF.MetaDataClientCaCertStream;

  public CABundleUpdateVert( KubernetesClient kubeClient, NatsTLSClient natsTlsClient, 
                             KeySecretManager keyCache, String serviceId, String namespace)
  {
    this.kubeClient      = kubeClient;
    this.natsTlsClient   = natsTlsClient;
    this.keyCache        = keyCache;
    this.serviceId       = serviceId;
    this.namespace       = namespace;
  }

  @Override
  public void start(Promise<Void> startPromise)
  {
    this.workerExecutor     = vertx.createSharedWorkerExecutor("ca-handler-" + serviceId, 2);
    this.signedMsgProcessor = new SignedMessageProcessor(workerExecutor, keyCache);
    this.caSecretManager    = new CaSecretManager(kubeClient, namespace, serviceId);
        
    LOGGER.info("NatsCABundleUpdateVert initializing for service: {}", serviceId);
  
    // Initialization in worker thread to avoid blocking event loop
    workerExecutor.executeBlocking(()-> 
    {
      try
      {
        startBundleConsumer();
        LOGGER.info("NatsCABundleUpdateVert initialized successfully for service: {}", serviceId);
      } 
      catch (Exception e)
      {
        LOGGER.error("Failed to initialize NatsCABundleUpdateVert for service: {}", serviceId, e);
        startPromise.fail(e);
      }

      return ServiceCoreIF.SUCCESS;
    }).onSuccess(v -> startPromise.complete())
      .onFailure(startPromise::fail);
  }

  @Override
  public void stop(Promise<Void> stopPromise)
  {
    LOGGER.info("Stopping NatsCABundleUpdateVert for service: {}", serviceId);
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
      
      if (caSecretManager != null)
        caSecretManager.close();
          
      LOGGER.info("NatsCABundleUpdateVert cleaned up for service: {}", serviceId);
    } 
    catch (Exception e)
    {
      LOGGER.error("Error during cleanup: {}", e.getMessage(), e);
    }
  }
 
  /**
   * Message handler for Service Bundles
   */
  private MessageHandler bundleMsgHandler() 
  {
    return (msg) -> 
    {
      workerExecutor.executeBlocking(() -> 
      {
        try 
        {
          handleBundleMsg(msg);
          msg.ack();
          LOGGER.info("NatsCABundleUpdateVert - Message Received and Ack'd");
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

  private String startBundleConsumer() 
    throws Exception
  {
    LOGGER.info("NatsCABundleUpdateVert.startBundleConsumer() - Starting CA bundle consumer");

    workerExecutor.executeBlocking(() -> 
    {
      try
      {
        MessageHandler bundleMsgHandler = bundleMsgHandler();

        String subject = ServiceCoreIF.KeyExchangeStreamBase + consumerSubjectId;
        String consumerName = serviceId + "-ca-update-" + UUID.randomUUID().toString();
 
        natsTlsClient.getConsumerPoolManager()
          .getOrCreateConsumer(subject, consumerName, bundleMsgHandler)
          .onSuccess(subscription -> 
          {
            LOGGER.info("NatsCABundleUpdateVert: Subscribed to CA Bundle topic: {}", subject);
          })
         .onFailure(ex -> 
          {
            LOGGER.error("Failed to subscribe to CA Bundle topic", ex);
          });
        
        return ServiceCoreIF.SUCCESS;
      } 
      catch (Exception e)
      {
        LOGGER.error("Consumer creation exception. Error = - " + e.getMessage());
        cleanup();
        throw e;
      }
    }).onComplete(ar -> 
    {
      if (ar.failed()) 
      {
        LOGGER.error("Worker execution failed: {}", ar.cause().getMessage());
        throw new RuntimeException(ar.cause());
      } 
    });
    
    return ServiceCoreIF.SUCCESS;
  };

  /**
   * Handle incoming CA bundle message
   */
  private void handleBundleMsg(Message msg)
  {
    LOGGER.info("=======================================================================================");
    LOGGER.info("NatsCABundleUpdateVert.handleBundleMsg received CABundle msg.");
    LOGGER.info("=======================================================================================");

    // Decrypt, verify and obtain ServiceBundle bytes
    byte[] signedMsgBytes = msg.getData();
    
    signedMsgProcessor.obtainDomainObject(signedMsgBytes)
      .compose((byte[] requestBytes) -> 
       {
        // Deserialize ServiceBundle
        return workerExecutor.<CaBundle>executeBlocking(() -> {
          try 
          {
            return CaBundle.deSerialize(requestBytes);
          }
          catch (Exception e)
          {
            LOGGER.error("Error deserializing CaBundle: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to deserialize CaBundle", e);
          }
        });
      })
     .onSuccess(caBundle -> 
      {
        LOGGER.info("Successfully decrypted, deserialized, and verified caBundle for serviceId={}", serviceId);
        updateNatsConnections(caBundle);
      })
    .onFailure(err -> 
     {
       LOGGER.error("Failed to decrypt/process/verify ServiceBundle from additionalData", err);
     });
  }
  
  private void updateNatsConnections(CaBundle caBundle) {
    LOGGER.info("Updating NATS connections with CA bundle - Server: {}, Version: {}, Epoch: {}",
            caBundle.getServerId(), caBundle.getCaVersion(), caBundle.getCaEpochNumber());

    workerExecutor.executeBlocking(() -> {
        try {
            // Store the CA bundle in the appropriate Kubernetes secret
            caSecretManager.updateCaSecret(caBundle);

            LOGGER.info("CA secret updated successfully for service: {}", serviceId);

            // Notify NatsTLSClient of certificate change
            // This will trigger the certificate update process
            natsTlsClient.handleCaBundleUpdate(caBundle);

            LOGGER.info("NATS connection update completed for service: {}", serviceId);
            return ServiceCoreIF.SUCCESS;
        } catch (Exception e) {
            LOGGER.error("Failed to update NATS connections", e);
            throw new RuntimeException("CA bundle update failed", e);
        }
    })
    .onSuccess(result -> 
    {
        LOGGER.info("Successfully updated NATS connections with new CA bundle");
    })
    .onFailure(error -> 
     {
        LOGGER.error("Failed to update NATS connections with new CA bundle", error);
    });
  }  
}