package verticle;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.buffer.Buffer;

import core.crypto.KyberKEMCrypto;
import core.handler.KeySecretManager;
import core.model.KyberExchangeMessage;
import core.model.ServiceBundle;
import core.model.ServiceCoreIF;
import core.model.SharedSecretInfo;
import core.processor.SignedMessageProcessor;
import core.nats.NatsTLSClient;
import core.transport.SignedMessage;
import core.model.DilithiumKey;

import io.nats.client.JetStreamSubscription;
import io.nats.client.Message;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;

/**
 * Metadata Key Exchange Verticle - Async Pull Consumer Implementation
 * 
 * Processes Kyber key exchange requests from clients and responds with:
 * 1. Kyber key exchange response
 * 2. Encrypted ServiceBundle for the requesting service
 * 
 * Uses async pull consumer to fetch requests from KEY_EXCHANGE stream.
 * 
 * @author t-snyder
 * @date 2025-11-04
 */
public class MetadataKeyExchangeVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger(MetadataKeyExchangeVert.class);
  
  private static final String STREAM_NAME = "KEY_EXCHANGE";
  private static final int BATCH_SIZE = 5;
  private static final long FETCH_TIMEOUT_MS = 500;
  private static final long PULL_INTERVAL_MS = 100;

  private final NatsTLSClient natsTlsClient;
  private final KeySecretManager keyCache;
  private final String serviceId = "metadata";
  
  private WorkerExecutor workerExecutor;
  private JetStreamSubscription keyConsumer;
  private SignedMessageProcessor signedMessageProcessor;

  public MetadataKeyExchangeVert(NatsTLSClient natsTlsClient, KeySecretManager keyCache)
  {
    this.natsTlsClient = natsTlsClient;
    this.keyCache = keyCache;
  }

  @Override
  public void start(Promise<Void> startPromise)
  {
    try
    {
      workerExecutor = vertx.createSharedWorkerExecutor("metadata-key-exch", 2, 360000);
      signedMessageProcessor = new SignedMessageProcessor(workerExecutor, keyCache);
         
      startKeyExchConsumer()
        .onSuccess(res -> 
        {
          startPromise.complete();
          LOGGER.info("Metadata Key Exchange Vert started with async pull consumer");
        })
        .onFailure(e -> 
        {
          LOGGER.error("Failed to start KeyExchange consumer: {}", e.getMessage(), e);
          startPromise.fail(e);
        });
    } 
    catch (Exception e)
    {
      LOGGER.error("Failed to start MetadataKeyExchangeVert: {}", e.getMessage(), e);
      startPromise.fail(e);
    }
  }

  /**
   * Bind to async pull consumer for key exchange requests
   */
  private Future<Void> startKeyExchConsumer()
  {
    LOGGER.info("Binding to async pull consumer for key exchange: stream={} service={}", 
               STREAM_NAME, serviceId);

    Promise<Void> promise = Promise.promise();
    
    String durableName = "metadata-key-exchange-metadata";

    natsTlsClient.getConsumerPoolManager().bindPullConsumerAsync(
      STREAM_NAME,
      durableName,
      this::handleKeyExchangeMsgAsync,  // ASYNC handler - returns Future<Void>
      BATCH_SIZE,
      FETCH_TIMEOUT_MS,
      PULL_INTERVAL_MS
    )
    .onSuccess(sub -> 
    {
      this.keyConsumer = sub;
      LOGGER.info("Bound to async key exchange pull consumer: durable={} batchSize={}", 
                 durableName, BATCH_SIZE);
      promise.complete();
    })
    .onFailure(e -> 
    {
      LOGGER.error("Failed to bind async key-exchange consumer: {}", e.getMessage(), e);
      promise.fail(e);
    });
    
    return promise.future();
  }

  /**
   * Handle key exchange request message - ASYNC VERSION
   * Returns Future that completes when processing is done
   */
  private Future<Void> handleKeyExchangeMsgAsync(Message msg)
  {
    Promise<Void> promise = Promise.promise();
    
    try
    {
      LOGGER.info("========================================================================");
      LOGGER.info("MetadataKeyExchangeVert.handleKeyExchangeMsgAsync received msg at {}", Instant.now());

      KyberExchangeMessage kyberMsg = KyberExchangeMessage.deSerialize(msg.getData());
      if (kyberMsg == null)
      {
        String errMsg = "Could not deserialize KyberExchangeMessage";
        LOGGER.error(errMsg);
        promise.fail(new RuntimeException(errMsg));
        return promise.future();
      }

      String eventType = kyberMsg.getEventType();
      if (eventType == null && msg.getHeaders() != null)
      {
        eventType = msg.getHeaders().getFirst(ServiceCoreIF.MsgHeaderEventType);
      }
   
      LOGGER.info("KeyExchangeVert.handleKeyExchangeMsgAsync eventType: {}", eventType);

      if (eventType == null)
      {
        promise.fail(new RuntimeException("Message event type not found"));
        return promise.future();
      }
      
      if (ServiceCoreIF.KyberKeyRequest.equals(eventType) || 
          ServiceCoreIF.KyberRotateRequest.equals(eventType))
      {
        processKeyExchRequestAsync(kyberMsg)
          .onComplete(ar -> {
            if (ar.succeeded())
            {
              promise.complete();
            }
            else
            {
              promise.fail(ar.cause());
            }
          });
        return promise.future();
      }

      promise.fail(new RuntimeException("Message was not a key request or rotation: " + eventType));
    }
    catch (Exception e)
    {
      LOGGER.error("Exception in handleKeyExchangeMsgAsync: {}", e.getMessage(), e);
      promise.fail(e);
    }
    
    return promise.future();
  }

  /**
   * Process Kyber key exchange request and respond with ServiceBundle - ASYNC
   */
  protected Future<Void> processKeyExchRequestAsync(KyberExchangeMessage kyberMsg)
  {
    Promise<Void> promise = Promise.promise();
    
    try
    {
      LOGGER.info("Processing key exchange request from: {}", kyberMsg.getSourceSvcId());
     
      // Standard Kyber key exchange
      PublicKey publicKey = KyberKEMCrypto.decodePublicKey(kyberMsg.getPublicKey());
      SecretKeyWithEncapsulation encapsulation = 
        KyberKEMCrypto.processKyberExchangeRequest(KyberKEMCrypto.encodePublicKey(publicKey));
      SharedSecretInfo keyInfo = SharedSecretInfo.buildSharedSecret(
        kyberMsg, publicKey, encapsulation.getEncoded());
     
      String responseType = ServiceCoreIF.KyberKeyRequest.equals(kyberMsg.getEventType()) 
        ? ServiceCoreIF.KyberKeyResponse 
        : ServiceCoreIF.KyberRotateResponse;

      // Create base response
      KyberExchangeMessage responseMsg = new KyberExchangeMessage(
        kyberMsg.getSecretKeyId(),
        serviceId, 
        kyberMsg.getSourceSvcId(),
        responseType, 
        kyberMsg.getPublicKey(), 
        encapsulation.getEncapsulation(),
        kyberMsg.getCreateTime(),
        kyberMsg.getExpiryTime()
      );

      // Generate and attach signed ServiceBundle
      generateSignedMessage(kyberMsg.getSourceSvcId(), keyInfo)
        .onComplete(ar -> {
          try
          {
            if (ar.succeeded())
            {
              SignedMessage signedMsg = ar.result();
              
              LOGGER.info("=======================================================================");
              LOGGER.info("Created SignedMessage containing ServiceBundle");
              LOGGER.info("Message Type   = {}", signedMsg.getMessageType());
              LOGGER.info("Payload length = {}", signedMsg.getPayload().length);
               
              responseMsg.setAdditionalData(SignedMessage.serialize(signedMsg));
              LOGGER.info("Successfully processed key exchange for: {}", kyberMsg.getSourceSvcId());
            
              // Send response with encrypted ServiceBundle
              sendKeyExchangeMessage(kyberMsg.getSourceSvcId(), responseMsg);
              keyCache.putEncyptionSharedSecret(keyInfo);
              
              promise.complete();
            }
            else
            {
              LOGGER.error("Failed to process ServiceBundle for {}: {}", 
                kyberMsg.getSourceSvcId(), ar.cause().getMessage(), ar.cause());
                
              // Send response without ServiceBundle as fallback
              sendKeyExchangeMessage(kyberMsg.getSourceSvcId(), responseMsg);
              keyCache.putEncyptionSharedSecret(keyInfo);
              
              promise.complete(); // Still complete successfully (message sent without bundle)
            }
          }
          catch (Exception e)
          {
            String errMsg = "Error sending KyberMsg response: " + e.getMessage();
            LOGGER.error(errMsg, e);
            promise.fail(new RuntimeException(errMsg));
          }
        });
    }
    catch (Exception e)
    {
      LOGGER.error("Exception in processKeyExchRequestAsync: {}", e.getMessage(), e);
      promise.fail(e);
    }
    
    return promise.future();
  }

  /**
   * Get current ServiceBundle for target service
   */
  public Future<ServiceBundle> getCurrentServiceBundle(String serviceId) 
  {
    return vertx.eventBus().<Buffer>request(
      ServicesACLWatcherVert.SERVICE_BUNDLE_REQUEST_ADDR,
      serviceId
    )
    .compose(msg -> 
    {
      try 
      {
        ServiceBundle bundle = ServiceBundle.deSerialize(msg.body().getBytes());
        return Future.succeededFuture(bundle);
      } 
      catch (Exception e) 
      {
        return Future.failedFuture(e);
      }
    });
  }

  /**
   * Generate SignedMessage containing ServiceBundle encrypted with shared secret
   */
  private Future<SignedMessage> generateSignedMessage(String targetServiceId, SharedSecretInfo sharedSecret) 
  {
    LOGGER.info("Generating ServiceBundle for service: {}", targetServiceId);

    return getCurrentServiceBundle(targetServiceId)
      .compose(bundle -> 
        workerExecutor.executeBlocking(() -> 
        {
          byte[] serializedBundle = ServiceBundle.serialize(bundle);
          if (serializedBundle == null || serializedBundle.length == 0) 
          {
            throw new RuntimeException("Failed to serialize ServiceBundle for: " + targetServiceId);
          }
          return serializedBundle;
        })
      )
      .compose(serializedBundle ->
      {
        String subject = ServiceCoreIF.KeyExchangeStreamBase + targetServiceId;
        return signedMessageProcessor.createSignedMessage(
          targetServiceId,
          serializedBundle,
          "ServiceBundle",
          "ServiceBundle",
          subject,
          sharedSecret.getSharedSecret()
        );
      })
      .onFailure(err -> 
      {
        LOGGER.error("Failed to process ServiceBundle for service: {}", targetServiceId, err);
      });
  }
  
  /**
   * Send key exchange response message
   */
  private void sendKeyExchangeMessage(String targetServiceId, KyberExchangeMessage responseMsg)
  {
    LOGGER.info("Sending key exchange response to service: {}", targetServiceId);

    try 
    {
      byte[] responseBytes = KyberExchangeMessage.serialize(responseMsg);
      if (responseBytes == null || responseBytes.length == 0) 
      {
        LOGGER.warn("Failed to serialize KyberExchangeMessage for: {}", targetServiceId);
        return;
      }
      
      String subject = "metadata.key-exchange." + targetServiceId;
 
      natsTlsClient.publish(subject, responseBytes)
        .onSuccess(v -> LOGGER.info("Sent KyberExchangeMessage to subject: {}", subject))
        .onFailure(e -> LOGGER.error("Failed to send KyberExchangeMessage to {}: {}", 
                                     subject, e.getMessage(), e));
    } 
    catch (Exception e) 
    {
      LOGGER.error("Error sending KyberExchangeMessage: {}", e.getMessage(), e);
    }
  }
  
  @Override
  public void stop() throws Exception
  {
    LOGGER.info("Stopping Metadata Key Exchange Vert");

    if (workerExecutor != null)
    {
      workerExecutor.close();
    }
    
    if (keyConsumer != null) 
    {
      try 
      {
        keyConsumer.drain(Duration.ofSeconds(2));
        keyConsumer.unsubscribe();
      } 
      catch (Exception e) 
      {
        LOGGER.warn("Error closing key exchange subscription: {}", e.getMessage());
      }
    }

    LOGGER.info("Metadata Key Exchange Vert stopped");
  }
}
