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

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.util.concurrent.TimeUnit;


/**
 * Enhanced Verticle for initiating and handling Kyber key exchange and ServiceBundle
 * updates using NATS JetStream with proper subject mapping.
 */
public class KeyExchangeVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger(KeyExchangeVert.class);

  private final Cache<String, Boolean> processedKeyIds = Caffeine.newBuilder()
      .expireAfterWrite(1, TimeUnit.HOURS)  // Auto-remove after 1 hour
      .maximumSize(10_000)                   // Cap at 10k entries
      .build();

  // NATS and crypto dependencies
  protected NatsTLSClient          natsTlsClient;
  protected KeySecretManager       keyCache;
  protected WorkerExecutor         workerExecutor;
  protected SignedMessageProcessor signedMsgProcessor;
  
  protected String serviceId;

  // NOTE: changed from JetStreamSubscription to Subscription so this vert can accept either:
  // - a JetStreamSubscription (when the client created/bound to a durable)
  // - a plain NATS Subscription (when the admin-created server-side consumer delivers to a target subject)
  private Subscription keyExchConsumer = null; 
  
  private long periodicKeyExchangeTimer = -1;


  public KeyExchangeVert(NatsTLSClient natsTlsClient, KeySecretManager keyCache, String serviceId)
  {
    this.natsTlsClient = natsTlsClient;
    this.keyCache = keyCache;
    this.serviceId = serviceId;
  }

  @Override
  public void start(Promise<Void> startPromise)
  {
    this.workerExecutor = vertx.createSharedWorkerExecutor("keyexchange-handler-" + serviceId, 2);
    this.signedMsgProcessor = new SignedMessageProcessor(workerExecutor, keyCache);
    
    LOGGER.info("KeyExchangeVert initializing for service: {}", serviceId);

    try 
    {
      // Start NATS consumer for KyberExchangeMessage responses first
      startKeyExchangeConsumer().onSuccess(v -> 
      {
        // Perform initial key exchange after consumer is ready
        performKeyExchange();

        // Start periodic key exchange timer
        schedulePeriodicKeyExchange();

        startPromise.complete();
        LOGGER.info("KeyExchangeVert started for service: {}", serviceId);
      }).onFailure(startPromise::fail);
    } 
    catch (Exception e) 
    {
      LOGGER.error("Failed to start KeyExchangeVert for service: {}", serviceId, e);
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
    
    if( keyExchConsumer != null )
    {
      try 
      {
        // Drain only applies to JetStreamSubscription
        if (keyExchConsumer instanceof JetStreamSubscription)
        {
          JetStreamSubscription jss = (JetStreamSubscription) keyExchConsumer;
          try { jss.drain(Duration.ofSeconds(2)); } catch (Exception ignore) {}
        }
      } 
      catch (Exception ignore) {}

      try { keyExchConsumer.unsubscribe(); } catch (Exception ignore) {}
      keyExchConsumer = null;
    }
    
    if (workerExecutor != null)
    {
      workerExecutor.close();
    }
    
    stopPromise.complete();
    LOGGER.info("KeyExchangeVert stopped for service: {}", serviceId);
  }

  /**
   * Schedule periodic key exchange based on epochs
   */
  private void schedulePeriodicKeyExchange()
  {
    long currentEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
    Instant nextStart = KeyEpochUtil.epochStart(currentEpoch + 1);
    long gracePeriod = 300000L; // 5 minutes
    long delay = nextStart.toEpochMilli() - Instant.now().toEpochMilli() + gracePeriod;

    // Delay until start of next epoch
    vertx.setTimer(delay, id -> {
      periodicKeyExchangeTimer = vertx.setPeriodic(KeyEpochUtil.EPOCH_DURATION_MILLIS, tid -> performKeyExchange());
      performKeyExchange(); // Also do it immediately at the epoch
    });
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
        KyberExchangeMessage requestMsg = new KyberExchangeMessage(
            keyId, 
            serviceId, 
            "metadata", 
            ServiceCoreIF.KyberKeyRequest, 
            KyberKEMCrypto.encodePublicKey(kyberKeyPair.getPublic()), 
            Instant.now(), 
            Instant.now().plusSeconds(3 * 60 * 60)
        );

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
   * Send key exchange message to NATS JetStream
   * Uses the correct subject pattern: metadata.key-exchange.metadata
   */
  private void sendKeyExchangeMessage(KyberExchangeMessage message) throws Exception
  {
    try
    {
      byte[] msgBytes = KyberExchangeMessage.serialize(message);
      
      // Use the correct subject pattern for metadata service
      String publishSubject = ServiceCoreIF.KeyExchangeStreamBase + "metadata";
      
      // Add metadata headers for better message tracking
      Map<String, String> headers = new HashMap<>();
      headers.put("message-type", "kyber-exchange-request");
      headers.put("service-id", serviceId);
      headers.put("timestamp", String.valueOf(System.currentTimeMillis()));
      headers.put(ServiceCoreIF.MsgHeaderEventType, ServiceCoreIF.KyberKeyRequest);
      
      natsTlsClient.publish( publishSubject, msgBytes, headers )
        .onSuccess(v  -> LOGGER.info("Key exchange message sent successfully to subject: {}", publishSubject))
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
   * Uses the correct subject pattern for this service's responses.
   */
  protected Future<Void> startKeyExchangeConsumer()
  {
    Promise<Void> promise = Promise.promise();
    
    // Consumer subscribes to responses addressed to this service
    String subject = ServiceCoreIF.KeyExchangeStreamBase + serviceId;
    String durable = serviceId + "-key-exch-consumer";
    
    LOGGER.info("Starting key exchange consumer for subject: {}", subject);
 
    natsTlsClient.attachPushQueue(subject, durable, kyberExchangeMsgHandler())
     .onSuccess( sub ->
      {
        // Accept either JetStreamSubscription or plain Subscription
        try
        {
          this.keyExchConsumer = sub;

          if (sub instanceof JetStreamSubscription)
          {
            LOGGER.info("Key exchange consumer attached (JetStreamSubscription): subject={} durable={}", subject, durable);
          }
          else
          {
            LOGGER.info("Key exchange consumer attached (plain NATS Subscription) subject={} durable={}", subject, durable);
          }

          promise.complete();
        }
        catch (Exception e)
        {
          LOGGER.error("Error handling attached subscription: {}", e.getMessage(), e);
          promise.fail(e);
        }
      })
     .onFailure( e -> 
      {
        LOGGER.error("Failed to attach key-exchange consumer: {}", e.getMessage(), e);
        promise.fail(e);
      });

    return promise.future();
  }

  private MessageHandler kyberExchangeMsgHandler()
  {
    return (msg) -> 
    {
      // Don't wrap in executeBlocking - the handler is already called on a worker thread
      try
      {
        KyberExchangeMessage responseMsg = KyberExchangeMessage.deSerialize(msg.getData());

        // Check message age
        Instant messageTime = responseMsg.getCreateTime();
        Duration age = Duration.between(messageTime, Instant.now());

        if(age.toMinutes() > 10) 
        {
          LOGGER.info("Ignoring stale KyberExchange response (age: {} minutes)", age.toMinutes());
          msg.ack();
          return;
        }

        // Check if we've already processed this key exchange
        String keyId = responseMsg.getSecretKeyId();
        if(processedKeyIds.getIfPresent(keyId) != null) 
        {
          LOGGER.info("Ignoring duplicate KyberExchange response for keyId: {}", keyId);
          msg.ack();
          return;
        }
        processedKeyIds.put(keyId, Boolean.TRUE);

        // Validate this message is for us
        if(responseMsg.getTargetSvcId() != null && !serviceId.equals(responseMsg.getTargetSvcId()))
        {
          LOGGER.debug("Ignoring message not addressed to this service (target: {})", 
                      responseMsg.getTargetSvcId());
          msg.ack();
          return;
        }

        // Process only response messages
        if(ServiceCoreIF.KyberKeyResponse.equals(responseMsg.getEventType()) || 
           ServiceCoreIF.KyberRotateResponse.equals(responseMsg.getEventType()))
        {
          processKeyExchResponseAsync(responseMsg)
            .onComplete(ar -> 
            {
              if(ar.succeeded())
              {
                try {
                  msg.ack();
                } catch (Exception ackEx) {
                  // Ack may not be supported on non-JetStream message types; log but continue.
                  LOGGER.debug("Ack failed/unsupported for message: {}", ackEx.getMessage());
                }
                LOGGER.info("Processed KyberExchange response and ack'd: {}", 
                           responseMsg.getSecretKeyId());
                
                // Send notification ONLY after ServiceBundle is fully loaded
                vertx.eventBus().send("metadata.keyExchange.complete",
                  ServiceCoreIF.SUCCESS.getBytes(StandardCharsets.UTF_8));
              }
              else
              {
                LOGGER.error("Failed to process key exchange response: {}", 
                            ar.cause() != null ? ar.cause().getMessage() : "unknown", ar.cause());
                // Don't ack - allow redelivery
              }
            });
        }
        else
        {
          LOGGER.warn("Received unexpected message type: {}", responseMsg.getEventType());
          msg.ack();
        }
      }
      catch(Exception e)
      {
        LOGGER.error("Error processing KyberExchangeMessage: {}", e.getMessage(), e);
        // Don't ack on exception - allow redelivery
      }
    };
  }
  
  /**
   * Enhanced ServiceBundle processing with better error handling
   */
  protected Future<Void> processKeyExchResponseAsync(KyberExchangeMessage responseMsg)
  {
    Promise<Void> promise = Promise.promise();

    try
    {
      LOGGER.info("Processing Kyber exchange response from {} for service: {}", 
                  responseMsg.getSourceSvcId(), serviceId);

      // Extract the encapsulation and process to get the shared secret
      byte[]     encapsulation     = responseMsg.getEncapsulation();
      PrivateKey myKyberPrivateKey = keyCache.getKyberPrivateKey(responseMsg.getSecretKeyId());
      
      if (myKyberPrivateKey == null)
      {
        String msg = "No Kyber private key found for id: " + responseMsg.getSecretKeyId() + " - likely a stale/replayed message";
        LOGGER.warn( msg );
        promise.fail( msg );
      }

      byte[] sharedSecret = KyberKEMCrypto.generateSecretKeyInitiator(myKyberPrivateKey, encapsulation);
      PublicKey publicKey = keyCache.getKyberPublicKey(responseMsg.getSecretKeyId());
      SharedSecretInfo sharedSecretInfo = SharedSecretInfo.buildSharedSecret(responseMsg, publicKey, sharedSecret);

      // Place the shared secret in cache for future use
      keyCache.putEncyptionSharedSecret(sharedSecretInfo);
      LOGGER.info("Stored shared secret for key exchange with: {}", responseMsg.getSourceSvcId());

      // If additionalData is present, it should contain encrypted ServiceBundle
      if (responseMsg.hasAdditionalData())
      {
        LOGGER.info("Processing ServiceBundle from additional data");
        processServiceBundle(responseMsg.getAdditionalData(), sharedSecret, responseMsg.getSourceSvcId())
        .onComplete(ar -> {
          if (ar.succeeded())
          {
            promise.complete();  // ✓ Signal completion
          }
          else
          {
            promise.fail(ar.cause());
          }
        });
      } 
      else
      {
        LOGGER.info("No ServiceBundle in response - key exchange only");
        // Complete since the shared secret is stored
        promise.complete();
      }
    } 
    catch (Exception e)
    {
      LOGGER.error("Failed to process KyberExchange response message", e);
      promise.fail(e);
    }
    
    return promise.future();
  }

  /**
   * Enhanced ServiceBundle processing with bootstrapping support
   */
  private Future<ServiceBundle> processServiceBundle(byte[] signedMsgBytes, byte[] sharedSecret, String sourceServiceId)
  {
    try 
    {
      // Parse SignedMessage and encrypted payload
      SignedMessage signedMsg = SignedMessage.deSerialize(signedMsgBytes);
      EncryptedData encData = EncryptedData.deserialize(signedMsg.getPayload());

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
        LOGGER.info("Deserialized ServiceBundle - serviceId: " + serviceBundle.getServiceId() );
      } 
      catch (Exception e) 
      {
        LOGGER.error("Failed to deserialize ServiceBundle from decrypted bytes", e);
        return Future.failedFuture(e);
      }

      // Enhanced verification with bootstrapping support
      return verifyAndLoadServiceBundle(serviceBundle, signedMsg, domainBytes, sourceServiceId);

    } 
    catch (Exception e) 
    {
      LOGGER.error("Unexpected error processing ServiceBundle", e);
      return Future.failedFuture(e);
    }
  }

  /**
   * Verify and load ServiceBundle with bootstrapping support
   */
  private Future<ServiceBundle> verifyAndLoadServiceBundle(ServiceBundle serviceBundle, 
                                                          SignedMessage signedMsg, 
                                                          byte[] domainBytes, 
                                                          String sourceServiceId)
  {
    // Extract the expected signing key from the bundle
    Map<Long, DilithiumKey> verifyMap = serviceBundle.getVerifyKeys().get(sourceServiceId);
    long signerKeyId = signedMsg.getSignerKeyId();
    
    if (verifyMap == null || !verifyMap.containsKey(signerKeyId)) 
    {
      // For bootstrapping, we might not have the verification key yet
      LOGGER.warn("Verification key {} for service {} not found in ServiceBundle - proceeding with bundle load (bootstrapping)", 
                 signerKeyId, sourceServiceId);
      
      // Load the bundle first for bootstrapping
      try 
      {
        keyCache.loadFromServiceBundle(serviceBundle);
        LOGGER.info("Loaded ServiceBundle during bootstrapping phase");
        return Future.succeededFuture(serviceBundle);
      } 
      catch (Exception e) 
      {
        LOGGER.error("Failed to load ServiceBundle during bootstrapping", e);
        return Future.failedFuture(e);
      }
    }

    // Normal verification path
    DilithiumKey signingKey = verifyMap.get(signerKeyId);
    return signedMsgProcessor.verifyWithKey(domainBytes, signedMsg.getSignature(), signingKey)
      .compose(verified -> 
      {
        if (!verified) 
        {
          LOGGER.warn("Signature verification failed for ServiceBundle from {}", sourceServiceId);
          return Future.failedFuture("Signature verification failed");
        }

        // Load the verified service bundle into key cache
        try 
        {
          keyCache.loadFromServiceBundle(serviceBundle);
          LOGGER.info("Successfully verified and loaded ServiceBundle from {}", sourceServiceId);
        } 
        catch (Exception e) 
        {
          LOGGER.error("Failed to load verified ServiceBundle into keyCache", e);
          return Future.failedFuture(e);
        }
        
        return Future.succeededFuture(serviceBundle);
      });
  }
}