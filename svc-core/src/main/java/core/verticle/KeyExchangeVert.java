package core.verticle;

import core.crypto.AesGcmHkdfCrypto;
import core.crypto.EncryptedData;
import core.crypto.KyberKEMCrypto;
import core.handler.KeySecretManager;
import core.model.DilithiumKey;
import core.model.KyberExchangeMessage;
import core.model.ServiceBundle;
import core.model.ServiceCoreIF;
import core.model.SharedSecretInfo;
import core.processor.SignedMessageProcessor;
import core.nats.NatsTLSClient;
import core.transport.SignedMessage;
import core.utils.KeyEpochUtil;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;

import io.nats.client.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Verticle for initiating and handling Kyber key exchange and ServiceBundle
 * updates using NATS JetStream.
 * - On startup: initiates a Kyber key exchange with Metadata service.
 * - On each epoch (3 hours): re-initiates key exchange.
 * - Consumes KyberExchangeMessage responses, decrypts ServiceBundles from additionalData
 * if present.
 */
public class KeyExchangeVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger( KeyExchangeVert.class);

  // NATS and crypto dependencies
  protected NatsTLSClient          natsTlsClient;
  protected KeySecretManager       keyCache;
  protected WorkerExecutor         workerExecutor;
  protected SignedMessageProcessor signedMsgProcessor;
  
  protected String serviceId;
  protected String kyberExchPublishSubject;  // Subject to publish KyberExchangeMessage
  protected String kyberExchResponseSubject;
  protected String serviceBundleSubject;     // Subject to receive push ServiceBundle messages
 
  private long periodicKeyExchangeTimer = -1;

  public KeyExchangeVert( NatsTLSClient natsTlsClient, KeySecretManager keyCache, 
                          String serviceId, String kyberExchPublishSubject, 
                          String kyberExchResponseSubject, String serviceBundleSubject)
  {
    this.natsTlsClient              = natsTlsClient;
    this.keyCache                   = keyCache;
    this.serviceId                  = serviceId;
    this.kyberExchPublishSubject    = kyberExchPublishSubject;
    this.kyberExchResponseSubject   = kyberExchResponseSubject;
    this.serviceBundleSubject       = serviceBundleSubject;
  }

  @Override
  public void start(Promise<Void> startPromise)
  {
    this.workerExecutor     = vertx.createSharedWorkerExecutor("keyexchange-handler-" + serviceId, 2);
    this.signedMsgProcessor = new SignedMessageProcessor(workerExecutor, keyCache);
    
    LOGGER.info("NatsKeyExchangeVert initializing for service: {}", serviceId);

    try 
    {
      // Perform initial key exchange on startup
      performKeyExchange();

      // Start a timer for periodic (epoch-based) key exchange/rotation (every 3 hours on epoch)
      long    currentEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
      Instant nextStart    = KeyEpochUtil.epochStart(currentEpoch + 1);
      long    gracePeriod  = 300000L; // 5 minutes
      long    delay        = nextStart.toEpochMilli() - Instant.now().toEpochMilli() + gracePeriod;

      // Delay until start of next epoch
      vertx.setTimer(delay, id -> 
      {
        periodicKeyExchangeTimer = vertx.setPeriodic(KeyEpochUtil.EPOCH_DURATION_MILLIS, tid -> performKeyExchange());
        performKeyExchange(); // Also do it immediately at the epoch
      });

      // Start a NATS consumer for KyberExchangeMessage responses
      startKeyExchangeConsumer();

      startPromise.complete();
      LOGGER.info("NatsKeyExchangeVert started for service: {}", serviceId);
    } 
    catch (Exception e) 
    {
      LOGGER.error("Failed to start NatsKeyExchangeVert for service: {}", serviceId, e);
      startPromise.fail(e);
    }
  }

  @Override
  public void stop(Promise<Void> stopPromise)
  {
    if (periodicKeyExchangeTimer != -1)
    {
      vertx.cancelTimer(periodicKeyExchangeTimer);
    }
    if (workerExecutor != null)
    {
      workerExecutor.close();
    }
    
    stopPromise.complete();
    LOGGER.info("NatsKeyExchangeVert stopped for service: {}", serviceId);
  }

  /**
   * Initiate a Kyber key exchange request to the Metadata service.
   */
  protected void performKeyExchange()
  {
    workerExecutor.executeBlocking(() -> 
    {
      try
      {
        KeyPair kyberKeyPair = KyberKEMCrypto.generateKeyPair();
        String keyId = UUID.randomUUID().toString();
        keyCache.putKyberKeyPair(keyId, kyberKeyPair);

        // Build KyberExchangeMessage (request)
        KyberExchangeMessage requestMsg = new KyberExchangeMessage(keyId, serviceId, "metadata", 
                                                                 ServiceCoreIF.KyberKeyRequest, 
                                                                 KyberKEMCrypto.encodePublicKey(kyberKeyPair.getPublic()), 
                                                                 Instant.now(), 
                                                                 Instant.now().plusSeconds(3 * 60 * 60));

        // Send message with enhanced error handling
        sendKeyExchangeMessage(requestMsg);

        LOGGER.info("Sent Kyber key exchange request to Metadata service (keyId={})", keyId);
        return ServiceCoreIF.SUCCESS;
      } 
      catch (Exception e)
      {
        LOGGER.error("Failed to perform Kyber key exchange request", e);
        throw new RuntimeException(e);
      }
    });
  }

  /**
   * Send key exchange message to NATS JetStream with enhanced configuration
   */
  private void sendKeyExchangeMessage(KyberExchangeMessage message) throws Exception
  {
    try
    {
      byte[] msgBytes = KyberExchangeMessage.serialize(message);
      
      // Add metadata headers for better message tracking
      Map<String, String> headers = new HashMap<>();
      headers.put("message-type", "kyber-exchange-request");
      headers.put("service-id", serviceId);
      headers.put("timestamp", String.valueOf(System.currentTimeMillis()));
      
      natsTlsClient.publish(kyberExchPublishSubject, msgBytes, headers)
        .onSuccess(v -> LOGGER.debug("Key exchange message sent successfully to subject: {}", kyberExchPublishSubject))
        .onFailure(ex -> LOGGER.error("Failed to send key exchange message: {}", ex.getMessage(), ex));
    } 
    catch (Exception e)
    {
      LOGGER.error("Failed to send key exchange message (serialization): {}", e.getMessage(), e);
      throw new RuntimeException(e);
    }
  }

  /**
   * Start NATS consumer for KyberExchangeMessage responses from Metadata.
   */
  protected void startKeyExchangeConsumer()
  {
    String consumerName = serviceId + "-kyber-exch-consumer";
    
    natsTlsClient.getConsumerPoolManager()
     .getOrCreateConsumer(kyberExchResponseSubject, consumerName, kyberExchangeMsgHandler())
     .onSuccess(subscription -> 
      {
        LOGGER.info("NatsKeyExchangeVert: Subscribed to KyberExchange subject: {}", kyberExchResponseSubject);
      })
     .onFailure(ex -> 
      {
        LOGGER.error("Failed to subscribe to KyberExchange subject", ex);
      });
  }

  /**
   * Message handler for KyberExchangeMessage responses.
   */
  private MessageHandler kyberExchangeMsgHandler()
  {
    return (msg) -> 
    {
      workerExecutor.executeBlocking(() -> {
        try
        {
          KyberExchangeMessage responseMsg = KyberExchangeMessage.deSerialize(msg.getData());
          if (responseMsg.getTargetSvcId() != null && !serviceId.equals(responseMsg.getTargetSvcId()))
          {
            // Ignore messages not addressed to this service
            msg.ack();
            return ServiceCoreIF.SUCCESS;
          }
 
          processKeyExchResponse(responseMsg);
          msg.ack();
          LOGGER.info("Processed KyberExchange response and ack'd: {}", responseMsg.getSecretKeyId());

          vertx.eventBus().send("metadata.keyExchange.complete", ServiceCoreIF.SUCCESS.getBytes());
          
          return ServiceCoreIF.SUCCESS;
        } 
        catch (Exception e)
        {
          LOGGER.error("Error processing KyberExchangeMessage: {}", e.getMessage(), e);
          throw new RuntimeException(e);
        }
      });
    };
  }

  /**
   * Handles KyberExchangeMessage responses.
   * - Derives the shared secret
   * - Caches it
   * - Processes ServiceBundle in additionalData if present
   */
  protected void processKeyExchResponse(KyberExchangeMessage responseMsg)
  {
    try
    {
      LOGGER.info("Processing Kyber exchange response from {} for service: {}", 
                  responseMsg.getSourceSvcId(), serviceId);

      // Extract the encapsulation and process to get the shared secret
      byte[]     encapsulation     = responseMsg.getEncapsulation();
      PrivateKey myKyberPrivateKey = keyCache.getKyberPrivateKey(responseMsg.getSecretKeyId());
      if (myKyberPrivateKey == null)
      {
        throw new IllegalStateException("No Kyber private key found for id: " + responseMsg.getSecretKeyId());
      }

      byte[]           sharedSecret     = KyberKEMCrypto.generateSecretKeyInitiator(myKyberPrivateKey, encapsulation);
      PublicKey        publicKey        = keyCache.getKyberPublicKey(responseMsg.getSecretKeyId());
      SharedSecretInfo sharedSecretInfo = SharedSecretInfo.buildSharedSecret(responseMsg, publicKey, sharedSecret);

      // Place the shared secret in cache for future use
      keyCache.putEncyptionSharedSecret(sharedSecretInfo);

      // If additionalData is present, it should contain encrypted ServiceBundle
      if (responseMsg.hasAdditionalData())
      {
        LOGGER.info("Additional data found in KyberExchangeMessage; attempting to decrypt ServiceBundle(s)");
        processServiceBundle(responseMsg.getAdditionalData(), sharedSecret, responseMsg.getSourceSvcId());
      } 
      else
      {
        LOGGER.warn("No additional data present in KyberExchangeMessage; no ServiceBundle to process.");
      }
    } 
    catch (Exception e)
    {
      LOGGER.error("Failed to process KyberExchange response message", e);
    }
  }

  /**
   * Decrypt, verify (using keys embedded in the bundle), and load the ServiceBundle.
   *
   * Steps:
   *  1) deserialize SignedMessage and decrypt payload with provided sharedSecret
   *  2) deserialize domain bytes into ServiceBundle
   *  3) extract the metadata service public key from serviceBundle.verifyKeys (using sourceServiceId)
   *  4) verify the SignedMessage signature using that public key (via SignedMessageProcessor.verifyWithKey)
   *  5) if verified, load the ServiceBundle into the keyCache
   *
   * @param signedMsgBytes  The additionalData field from KyberExchangeMessage (serialized SignedMessage)
   * @param sharedSecret    The Kyber-derived shared secret for decryption
   * @param sourceServiceId The service id that provided the bundle (e.g. "metadata")
   * @return Future<ServiceBundle> completed when bundle is loaded (or failed with reason)
   */
  private Future<ServiceBundle> processServiceBundle(byte[] signedMsgBytes, byte[] sharedSecret, String sourceServiceId)
  {
    try 
    {
      // parse SignedMessage and encrypted payload
      SignedMessage signedMsg = SignedMessage.deserialize(signedMsgBytes);
      EncryptedData encData   = EncryptedData.deserialize(signedMsg.getPayload());

      if (sharedSecret == null || sharedSecret.length == 0) 
      {
        return Future.failedFuture("Shared secret is missing for ServiceBundle decryption");
      }

      // Decrypt with AES helper
      AesGcmHkdfCrypto aes = new AesGcmHkdfCrypto();
      byte[] domainBytes;
      try 
      {
        domainBytes = aes.decrypt(encData, sharedSecret);
      } 
      catch (Exception e) 
      {
        LOGGER.error("Failed to decrypt ServiceBundle payload", e);
        return Future.failedFuture(e);
      }

      // Deserialize ServiceBundle
      final ServiceBundle serviceBundle;
      try 
      {
        serviceBundle = ServiceBundle.deSerialize(domainBytes);
      } 
      catch (Exception e) 
      {
        LOGGER.error("Failed to deserialize ServiceBundle from decrypted bytes", e);
        return Future.failedFuture(e);
      }
    
      // Extract the expected signing key (from the bundle's verifyKeys for sourceServiceId)
      Map<Long, DilithiumKey> verifyMap   = serviceBundle.getVerifyKeys().get(sourceServiceId);
      long                    signerKeyId = signedMsg.getSignerKeyId();
      
      if (verifyMap == null || !verifyMap.containsKey(signerKeyId)) 
      {
        String err = "Signing key " + signerKeyId + " for service " + sourceServiceId + " not found in ServiceBundle.verifyKeys";
        LOGGER.warn(err);
        return io.vertx.core.Future.failedFuture(err);
      }
      DilithiumKey signingKey = verifyMap.get(signerKeyId);

      // Verify signature using the key from the bundle
      return signedMsgProcessor.verifyWithKey(domainBytes, signedMsg.getSignature(), signingKey)
        .compose(verified -> 
        {
          if (!verified) 
          {
            LOGGER.warn("Signature verification failed for ServiceBundle from {}", sourceServiceId);
            return Future.failedFuture("Signature invalid");
          }

          // load the service bundle into key cache
          try 
          {
            keyCache.loadFromServiceBundle(serviceBundle);
          } 
          catch (Exception e) 
          {
            LOGGER.error("Failed to load ServiceBundle into keyCache", e);
            return Future.failedFuture(e);
          }
          
          return Future.succeededFuture(serviceBundle);
        });

    } 
    catch (Exception e) 
    {
      LOGGER.error("Unexpected error processing ServiceBundle", e);
      return Future.failedFuture(e);
    }
  }  
}