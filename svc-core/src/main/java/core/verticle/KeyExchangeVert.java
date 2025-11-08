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
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Key Exchange Verticle for Client Services - Pull Consumer Implementation
 * 
 * Initiates Kyber key exchange with metadata service and processes responses.
 * Uses pull consumer to fetch key exchange responses.
 */
public class KeyExchangeVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger(KeyExchangeVert.class);

  private static final String STREAM_NAME = "KEY_EXCHANGE";
  private static final int BATCH_SIZE = 5;
  private static final long FETCH_TIMEOUT_MS = 500;
  private static final long PULL_INTERVAL_MS = 100;

  private final Cache<String, Boolean> processedKeyIds = Caffeine.newBuilder()
      .expireAfterWrite(1, TimeUnit.HOURS)
      .maximumSize(10_000)
      .build();

  protected NatsTLSClient natsTlsClient;
  protected KeySecretManager keyCache;
  protected WorkerExecutor workerExecutor;
  protected SignedMessageProcessor signedMsgProcessor;
  protected String serviceId;

  private JetStreamSubscription keyExchConsumer;
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
      // Start pull consumer for responses
      startKeyExchangeConsumer()
        .onSuccess(v -> 
        {
          // Perform initial key exchange
          performKeyExchange();

          // Start periodic key exchange
          schedulePeriodicKeyExchange();

          startPromise.complete();
          LOGGER.info("KeyExchangeVert started with pull consumer for service: {}", serviceId);
        })
        .onFailure(startPromise::fail);
    } 
    catch (Exception e) 
    {
      LOGGER.error("Failed to start KeyExchangeVert for service: {}", serviceId, e);
      startPromise.fail(e);
    }
  }

  /**
   * Bind to pull consumer for key exchange responses - ASYNC VERSION
   */
  protected Future<Void> startKeyExchangeConsumer()
  {
    LOGGER.info("Binding to key exchange pull consumer: stream={} service={}", 
               STREAM_NAME, serviceId);

    Promise<Void> promise = Promise.promise();
    
    String durableName = "metadata-key-exchange-" + serviceId;

    natsTlsClient.getConsumerPoolManager().bindPullConsumerAsync(
      STREAM_NAME,
      durableName,
      this::handleKeyExchangeResponseAsync,  // ASYNC handler - returns Future<Void>
      BATCH_SIZE,
      FETCH_TIMEOUT_MS,
      PULL_INTERVAL_MS
    )
    .onSuccess(sub -> 
    {
      this.keyExchConsumer = sub;
      LOGGER.info("Bound to key exchange pull consumer: service={} durable={}", 
                 serviceId, durableName);
      promise.complete();
    })
    .onFailure(e -> 
    {
      LOGGER.error("Failed to bind key-exchange consumer: {}", e.getMessage(), e);
      promise.fail(e);
    });

    return promise.future();
  }

  /**
   * Handle key exchange response message - ASYNC VERSION
   * Returns Future that completes when processing is done
   */
  private Future<Void> handleKeyExchangeResponseAsync(Message msg)
  {
    Promise<Void> promise = Promise.promise();
    
    try {
      LOGGER.info("🔵 handleKeyExchangeResponseAsync ENTRY (thread: {})", 
                  Thread.currentThread().getName());
      
      KyberExchangeMessage responseMsg = KyberExchangeMessage.deSerialize(msg.getData());

      // Check message age
      Instant messageTime = responseMsg.getCreateTime();
      Duration age = Duration.between(messageTime, Instant.now());

      if (age.toMinutes() > 10) 
      {
        LOGGER.info("Ignoring stale KyberExchange response (age: {} minutes, keyId: {})", 
                    age.toMinutes(), responseMsg.getSecretKeyId());
        promise.complete(); // Complete successfully = ack and remove
        return promise.future();
      }

      // Check for duplicates
      String keyId = responseMsg.getSecretKeyId();
      if (processedKeyIds.getIfPresent(keyId) != null) 
      {
        LOGGER.info("Ignoring duplicate KyberExchange response for keyId: {}", keyId);
        promise.complete();
        return promise.future();
      }
      processedKeyIds.put(keyId, Boolean.TRUE);

      // Validate this message is for us
      if (responseMsg.getTargetSvcId() != null && 
          !serviceId.equals(responseMsg.getTargetSvcId()))
      {
        LOGGER.debug("Ignoring message not addressed to this service (target: {}, keyId: {})", 
                    responseMsg.getTargetSvcId(), keyId);
        promise.complete();
        return promise.future();
      }

      // Process only response messages
      if (!ServiceCoreIF.KyberKeyResponse.equals(responseMsg.getEventType()) && 
          !ServiceCoreIF.KyberRotateResponse.equals(responseMsg.getEventType()))
      {
        LOGGER.warn("Received unexpected message type: {} (keyId: {})", 
                    responseMsg.getEventType(), keyId);
        promise.complete();
        return promise.future();
      }

      LOGGER.info("🔑 Processing KyberExchange response for keyId: {} (thread: {})", 
                  keyId, Thread.currentThread().getName());

      // Process the response ASYNC - NO BLOCKING .get()
      processKeyExchResponseAsync(responseMsg)
        .onComplete(ar -> {
          if (ar.succeeded()) {
            LOGGER.info("✅ Processed KyberExchange response: {}", keyId);
            
            // Send event bus notification
            LOGGER.info("📢 Sending event bus notification for keyId: {}", keyId);
            vertx.eventBus().send("metadata.keyExchange.complete",
              ServiceCoreIF.SUCCESS.getBytes(StandardCharsets.UTF_8));
            LOGGER.info("✅ Event bus notification sent for keyId: {}", keyId);
            
            promise.complete(); // Success = ack
          } else {
            LOGGER.error("❌ Failed to process KyberExchange response for keyId: {}: {}", 
                         keyId, ar.cause() != null ? ar.cause().getMessage() : "unknown", ar.cause());
            promise.fail(ar.cause()); // Failure = nak
          }
        });
        
    } catch (Exception e) {
      LOGGER.error("❌ Exception in handleKeyExchangeResponseAsync: {}", e.getMessage(), e);
      promise.fail(e);
    }
    
    return promise.future();
  }  
  
  /**
   * Bind to pull consumer for key exchange responses
  protected Future<Void> startKeyExchangeConsumer()
  {
    LOGGER.info("Binding to key exchange pull consumer: stream={} service={}", 
               STREAM_NAME, serviceId);

    Promise<Void> promise = Promise.promise();
    
    String durableName = "metadata-key-exchange-" + serviceId;

    natsTlsClient.bindPullConsumer(
      STREAM_NAME,
      durableName,
      this::handleKeyExchangeResponse,
      BATCH_SIZE,
      FETCH_TIMEOUT_MS,
      PULL_INTERVAL_MS
    )
    .onSuccess(sub -> 
    {
      this.keyExchConsumer = sub;
      LOGGER.info("Bound to key exchange pull consumer: service={} durable={}", 
                 serviceId, durableName);
      promise.complete();
    })
    .onFailure(e -> 
    {
      LOGGER.error("Failed to bind key-exchange consumer: {}", e.getMessage(), e);
      promise.fail(e);
    });

    return promise.future();
  }
   */

  /**
   * Handle key exchange response message
   * Called by pull loop - exceptions trigger nak
  private void handleKeyExchangeResponse(Message msg) throws Exception
  {
    LOGGER.info("🔵 handleKeyExchangeResponse ENTRY (thread: {})", Thread.currentThread().getName());
    
    KyberExchangeMessage responseMsg = KyberExchangeMessage.deSerialize(msg.getData());

    // Check message age
    Instant messageTime = responseMsg.getCreateTime();
    Duration age = Duration.between(messageTime, Instant.now());

    if (age.toMinutes() > 10) 
    {
      LOGGER.info("Ignoring stale KyberExchange response (age: {} minutes, keyId: {})", 
                  age.toMinutes(), responseMsg.getSecretKeyId());
      return;
    }

    // Check for duplicates
    String keyId = responseMsg.getSecretKeyId();
    if (processedKeyIds.getIfPresent(keyId) != null) 
    {
      LOGGER.info("Ignoring duplicate KyberExchange response for keyId: {}", keyId);
      return;
    }
    processedKeyIds.put(keyId, Boolean.TRUE);

    // Validate this message is for us
    if (responseMsg.getTargetSvcId() != null && 
        !serviceId.equals(responseMsg.getTargetSvcId()))
    {
      LOGGER.debug("Ignoring message not addressed to this service (target: {}, keyId: {})", 
                  responseMsg.getTargetSvcId(), keyId);
      return;
    }

    // Process only response messages
    if (!ServiceCoreIF.KyberKeyResponse.equals(responseMsg.getEventType()) && 
        !ServiceCoreIF.KyberRotateResponse.equals(responseMsg.getEventType()))
    {
      LOGGER.warn("Received unexpected message type: {} (keyId: {})", 
                  responseMsg.getEventType(), keyId);
      return;
    }

    LOGGER.info("🔑 Processing KyberExchange response for keyId: {} (thread: {})", 
                keyId, Thread.currentThread().getName());

    // Process the response
    LOGGER.info("🟡 About to call processKeyExchResponseAsync for keyId: {}", keyId);
    
    Future<Void> processingFuture = processKeyExchResponseAsync(responseMsg);
    
    LOGGER.info("🟡 processKeyExchResponseAsync returned Future for keyId: {}", keyId);
    LOGGER.info("🟡 About to block on .get() for keyId: {}", keyId);
    
    try 
    {
      processingFuture
        .toCompletionStage()
        .toCompletableFuture()
        .get(30, TimeUnit.SECONDS); // ADD TIMEOUT TO THE .get() CALL
      
      LOGGER.info("✅ .get() completed successfully for keyId: {}", keyId);
    } 
    catch( TimeoutException te ) 
    {
      LOGGER.error("❌ .get() TIMED OUT after 30 seconds for keyId: {}", keyId);
      throw new RuntimeException("Processing timeout", te);
    } 
    catch( Exception e ) 
    {
      LOGGER.error("❌ .get() threw exception for keyId: {}: {}", keyId, e.getMessage(), e);
      throw e;
    }
    
    LOGGER.info("📢 About to send event bus notification for keyId: {}", keyId);
    
    // Send notification after ServiceBundle is loaded
    vertx.eventBus().send("metadata.keyExchange.complete",
      ServiceCoreIF.SUCCESS.getBytes(StandardCharsets.UTF_8));
    
    LOGGER.info("✅ Event bus notification sent for keyId: {}", keyId);
    LOGGER.info("🔵 handleKeyExchangeResponse EXIT (thread: {})", Thread.currentThread().getName());
  }
   */
  
  /**
   * Handle key exchange response message
   * Called by pull loop - exceptions trigger nak
  private void handleKeyExchangeResponse(Message msg) throws Exception
  {
    KyberExchangeMessage responseMsg = KyberExchangeMessage.deSerialize(msg.getData());

    // Check message age
    Instant messageTime = responseMsg.getCreateTime();
    Duration age = Duration.between(messageTime, Instant.now());

    if (age.toMinutes() > 10) 
    {
      LOGGER.info("Ignoring stale KyberExchange response (age: {} minutes)", age.toMinutes());
      return;
    }

    // Check for duplicates
    String keyId = responseMsg.getSecretKeyId();
    if (processedKeyIds.getIfPresent(keyId) != null) 
    {
      LOGGER.info("Ignoring duplicate KyberExchange response for keyId: {}", keyId);
      return;
    }
    processedKeyIds.put(keyId, Boolean.TRUE);

    // Validate this message is for us
    if (responseMsg.getTargetSvcId() != null && 
        !serviceId.equals(responseMsg.getTargetSvcId()))
    {
      LOGGER.debug("Ignoring message not addressed to this service (target: {})", 
                  responseMsg.getTargetSvcId());
      return;
    }

    // Process only response messages
    if (!ServiceCoreIF.KyberKeyResponse.equals(responseMsg.getEventType()) && 
        !ServiceCoreIF.KyberRotateResponse.equals(responseMsg.getEventType()))
    {
      LOGGER.warn("Received unexpected message type: {}", responseMsg.getEventType());
      return;
    }

    // Process the response
    processKeyExchResponseAsync(responseMsg)
      .toCompletionStage()
      .toCompletableFuture()
      .get(); // Block to ensure processing completes before ack
    
    LOGGER.info("Processed KyberExchange response: {}", responseMsg.getSecretKeyId());
    
    // Send notification after ServiceBundle is loaded
    vertx.eventBus().send("metadata.keyExchange.complete",
      ServiceCoreIF.SUCCESS.getBytes(StandardCharsets.UTF_8));
  }
 */

  /**
   * Schedule periodic key exchange based on epochs
   */
  private void schedulePeriodicKeyExchange()
  {
    long currentEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
    Instant nextStart = KeyEpochUtil.epochStart(currentEpoch + 1);
    long gracePeriod = 300000L; // 5 minutes
    long delay = nextStart.toEpochMilli() - Instant.now().toEpochMilli() + gracePeriod;

    vertx.setTimer(delay, id -> 
    {
      periodicKeyExchangeTimer = vertx.setPeriodic(
        KeyEpochUtil.EPOCH_DURATION_MILLIS, 
        tid -> performKeyExchange()
      );
      performKeyExchange();
    });
  }

  /**
   * Initiate key exchange request to metadata service
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

        KyberExchangeMessage requestMsg = new KyberExchangeMessage(
          keyId, 
          serviceId, 
          "metadata", 
          ServiceCoreIF.KyberKeyRequest, 
          KyberKEMCrypto.encodePublicKey(kyberKeyPair.getPublic()), 
          Instant.now(), 
          Instant.now().plusSeconds(3 * 60 * 60)
        );

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
   * Send key exchange message to metadata service
   */
  private void sendKeyExchangeMessage(KyberExchangeMessage message) throws Exception
  {
    try
    {
      byte[] msgBytes = KyberExchangeMessage.serialize(message);
      
//      String publishSubject = ServiceCoreIF.KeyExchangeStreamBase + "metadata";
      String publishSubject = "metadata.key-exchange.metadata";      
  
      Map<String, String> headers = new HashMap<>();
      headers.put("message-type", "kyber-exchange-request");
      headers.put("service-id", serviceId);
      headers.put("timestamp", String.valueOf(System.currentTimeMillis()));
      headers.put(ServiceCoreIF.MsgHeaderEventType, ServiceCoreIF.KyberKeyRequest);
      
      natsTlsClient.publish(publishSubject, msgBytes, headers)
        .onSuccess(v -> LOGGER.info("Key exchange message sent to subject: {}", publishSubject))
        .onFailure(ex -> LOGGER.error("Failed to send key exchange message: {}", 
                                      ex.getMessage(), ex));
    } 
    catch (Exception e)
    {
      LOGGER.error("Failed to send key exchange message: {}", e.getMessage(), e);
      throw new RuntimeException(e);
    }
  }

  
  protected Future<Void> processKeyExchResponseAsync(KyberExchangeMessage responseMsg)
  {
    Promise<Void> promise = Promise.promise();

    try
    {
      LOGGER.info("🟢 processKeyExchResponseAsync ENTRY for keyId: {} (thread: {})", 
                  responseMsg.getSecretKeyId(), Thread.currentThread().getName());

      byte[] encapsulation = responseMsg.getEncapsulation();
      PrivateKey myKyberPrivateKey = keyCache.getKyberPrivateKey(responseMsg.getSecretKeyId());
      
      if (myKyberPrivateKey == null)
      {
        LOGGER.warn("No Kyber private key found for keyId: {} - ignoring stale/replayed message", 
                    responseMsg.getSecretKeyId());
        promise.complete();
        return promise.future();
      }

      LOGGER.info("🟢 Found Kyber private key for keyId: {}", responseMsg.getSecretKeyId());

      byte[] sharedSecret = KyberKEMCrypto.generateSecretKeyInitiator(myKyberPrivateKey, 
                                                                       encapsulation);
      LOGGER.info("🟢 Generated shared secret for keyId: {}", responseMsg.getSecretKeyId());
      
      java.security.PublicKey publicKey = keyCache.getKyberPublicKey(responseMsg.getSecretKeyId());
      SharedSecretInfo sharedSecretInfo = SharedSecretInfo.buildSharedSecret(responseMsg, 
                                                                              publicKey, 
                                                                              sharedSecret);

      keyCache.putEncyptionSharedSecret(sharedSecretInfo);
      LOGGER.info("🟢 Stored shared secret for keyId: {}", responseMsg.getSecretKeyId());

      // Process ServiceBundle if present
      if (responseMsg.hasAdditionalData())
      {
        LOGGER.info("🟢 Has additional data - processing ServiceBundle for keyId: {}", 
                    responseMsg.getSecretKeyId());
        
        processServiceBundle(responseMsg.getAdditionalData(), sharedSecret, 
                            responseMsg.getSourceSvcId())
          .onComplete(ar -> 
          {
            LOGGER.info("🟣 ServiceBundle processing callback invoked for keyId: {} (success: {}, thread: {})", 
                        responseMsg.getSecretKeyId(), ar.succeeded(), Thread.currentThread().getName());
            
            if (ar.succeeded())
            {
              LOGGER.info("✅ ServiceBundle processed successfully for keyId: {}", 
                          responseMsg.getSecretKeyId());
              promise.complete();
            }
            else
            {
              LOGGER.error("❌ ServiceBundle processing failed for keyId: {}: {}", 
                          responseMsg.getSecretKeyId(), 
                          ar.cause() != null ? ar.cause().getMessage() : "unknown", ar.cause());
              promise.fail(ar.cause());
            }
          });
      } 
      else
      {
        LOGGER.info("🟢 No ServiceBundle in response for keyId: {}", 
                    responseMsg.getSecretKeyId());
        promise.complete();
      }
      
      LOGGER.info("🟢 processKeyExchResponseAsync EXIT (returning future) for keyId: {}", 
                  responseMsg.getSecretKeyId());
    } 
    catch (Exception e)
    {
      LOGGER.error("❌ Exception in processKeyExchResponseAsync for keyId: {}: {}", 
                   responseMsg != null ? responseMsg.getSecretKeyId() : "unknown",
                   e.getMessage(), e);
      promise.fail(e);
    }
    
    return promise.future();
  }
  
  /**
   * Process key exchange response and extract ServiceBundle
   * Now handles stale messages gracefully by completing successfully instead of failing
  protected Future<Void> processKeyExchResponseAsync(KyberExchangeMessage responseMsg)
  {
    Promise<Void> promise = Promise.promise();

    try
    {
      LOGGER.info("Processing Kyber exchange response from {} for service: {}", 
                  responseMsg.getSourceSvcId(), serviceId);

      byte[] encapsulation = responseMsg.getEncapsulation();
      PrivateKey myKyberPrivateKey = keyCache.getKyberPrivateKey(responseMsg.getSecretKeyId());
      
      if (myKyberPrivateKey == null)
      {
        // Stale/replayed message - log and ack it (don't fail)
        LOGGER.info("No Kyber private key found for id: {} - ignoring stale/replayed message (will ack and remove)", 
                    responseMsg.getSecretKeyId());
        promise.complete();  // Success = message will be acked and removed from stream
        return promise.future();
      }

      byte[] sharedSecret = KyberKEMCrypto.generateSecretKeyInitiator(myKyberPrivateKey, 
                                                                       encapsulation);
      java.security.PublicKey publicKey = keyCache.getKyberPublicKey(responseMsg.getSecretKeyId());
      SharedSecretInfo sharedSecretInfo = SharedSecretInfo.buildSharedSecret(responseMsg, 
                                                                              publicKey, 
                                                                              sharedSecret);

      keyCache.putEncyptionSharedSecret(sharedSecretInfo);
      LOGGER.info("Stored shared secret for key exchange with: {}", responseMsg.getSourceSvcId());

      // Process ServiceBundle if present
      if (responseMsg.hasAdditionalData())
      {
        LOGGER.info("Processing ServiceBundle from additional data");
        processServiceBundle(responseMsg.getAdditionalData(), sharedSecret, 
                            responseMsg.getSourceSvcId())
          .onComplete(ar -> 
          {
            if (ar.succeeded())
            {
              promise.complete();
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
*/

  private Future<ServiceBundle> processServiceBundle( byte[] signedMsgBytes, byte[] sharedSecret, String sourceServiceId )
  {
    LOGGER.info( "🔷 processServiceBundle ENTRY (thread: {})", Thread.currentThread().getName() );

    try
    {
      LOGGER.info( "🔷 Deserializing SignedMessage" );
      SignedMessage signedMsg = SignedMessage.deSerialize( signedMsgBytes );

      LOGGER.info( "🔷 Deserializing EncryptedData from payload" );
      EncryptedData encData = EncryptedData.deserialize( signedMsg.getPayload() );

      if( sharedSecret == null || sharedSecret.length == 0 )
      {
        return Future.failedFuture( "Shared secret is missing for ServiceBundle decryption" );
      }

      LOGGER.info( "🔷 Decrypting ServiceBundle payload" );
      AesGcmHkdfCrypto aes = new AesGcmHkdfCrypto();
      byte[] domainBytes;
      try
      {
        domainBytes = aes.decrypt( encData, sharedSecret );
        LOGGER.info( "🔷 Decryption successful ({} bytes)", domainBytes.length );
      }
      catch( Exception e )
      {
        LOGGER.error( "❌ Failed to decrypt ServiceBundle payload", e );
        return Future.failedFuture( e );
      }

      LOGGER.info( "🔷 Deserializing ServiceBundle from decrypted bytes" );
      final ServiceBundle serviceBundle;
      try
      {
        serviceBundle = ServiceBundle.deSerialize( domainBytes );
        LOGGER.info( "🔷 Deserialized ServiceBundle - serviceId: {}", serviceBundle.getServiceId() );
      }
      catch( Exception e )
      {
        LOGGER.error( "❌ Failed to deserialize ServiceBundle", e );
        return Future.failedFuture( e );
      }

      LOGGER.info( "🔷 Calling verifyAndLoadServiceBundle" );
      Future<ServiceBundle> result = verifyAndLoadServiceBundle( serviceBundle, signedMsg, domainBytes, sourceServiceId );

      LOGGER.info( "🔷 processServiceBundle EXIT (returning future)" );
      return result;
    }
    catch( Exception e )
    {
      LOGGER.error( "❌ Unexpected error in processServiceBundle", e );
      return Future.failedFuture( e );
    }
  }
  
  /**
   * Process ServiceBundle from key exchange response
  private Future<ServiceBundle> processServiceBundle(byte[] signedMsgBytes, 
                                                     byte[] sharedSecret, 
                                                     String sourceServiceId)
  {
    try 
    {
      SignedMessage signedMsg = SignedMessage.deSerialize(signedMsgBytes);
      EncryptedData encData = EncryptedData.deserialize(signedMsg.getPayload());

      if (sharedSecret == null || sharedSecret.length == 0) 
      {
        return Future.failedFuture("Shared secret is missing for ServiceBundle decryption");
      }

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

      final ServiceBundle serviceBundle;
      try 
      {
        serviceBundle = ServiceBundle.deSerialize(domainBytes);
        LOGGER.info("Deserialized ServiceBundle - serviceId: {}", serviceBundle.getServiceId());
      } 
      catch (Exception e) 
      {
        LOGGER.error("Failed to deserialize ServiceBundle", e);
        return Future.failedFuture(e);
      }

      return verifyAndLoadServiceBundle(serviceBundle, signedMsg, domainBytes, sourceServiceId);
    } 
    catch (Exception e) 
    {
      LOGGER.error("Unexpected error processing ServiceBundle", e);
      return Future.failedFuture(e);
    }
  }
 */

  private Future<ServiceBundle> verifyAndLoadServiceBundle( ServiceBundle serviceBundle, SignedMessage signedMsg, byte[] domainBytes, String sourceServiceId )
  {
    LOGGER.info( "🔶 verifyAndLoadServiceBundle ENTRY (thread: {})", Thread.currentThread().getName() );

    Map<Long, DilithiumKey> verifyMap = serviceBundle.getVerifyKeys().get( sourceServiceId );
    long signerKeyId = signedMsg.getSignerKeyId();

    LOGGER.info( "🔶 Looking for verification key {} for service {}", signerKeyId, sourceServiceId );

    if( verifyMap == null || !verifyMap.containsKey( signerKeyId ) )
    {
      LOGGER.warn( "🔶 Verification key {} for service {} not found - proceeding with load (bootstrapping)", signerKeyId, sourceServiceId );

      try
      {
        LOGGER.info( "🔶 Loading ServiceBundle during bootstrapping phase" );
        keyCache.loadFromServiceBundle( serviceBundle );
        LOGGER.info( "✅ Loaded ServiceBundle during bootstrapping phase" );
        return Future.succeededFuture( serviceBundle );
      }
      catch( Exception e )
      {
        LOGGER.error( "❌ Failed to load ServiceBundle during bootstrapping", e );
        return Future.failedFuture( e );
      }
    }

    LOGGER.info( "🔶 Found verification key - verifying signature" );
    DilithiumKey signingKey = verifyMap.get( signerKeyId );

    LOGGER.info( "🔶 Calling signedMsgProcessor.verifyWithKey" );
    return signedMsgProcessor.verifyWithKey( domainBytes, signedMsg.getSignature(), signingKey ).compose( verified -> {
      LOGGER.info( "🔶 Signature verification callback invoked (verified: {}, thread: {})", verified, Thread.currentThread().getName() );

      if( !verified )
      {
        LOGGER.warn( "❌ Signature verification failed for ServiceBundle from {}", sourceServiceId );
        return Future.failedFuture( "Signature verification failed" );
      }

      try
      {
        LOGGER.info( "🔶 Loading verified ServiceBundle into KeyCache" );
        keyCache.loadFromServiceBundle( serviceBundle );
        LOGGER.info( "✅ Successfully verified and loaded ServiceBundle from {}", sourceServiceId );
      }
      catch( Exception e )
      {
        LOGGER.error( "❌ Failed to load verified ServiceBundle", e );
        return Future.failedFuture( e );
      }

      LOGGER.info( "🔶 verifyAndLoadServiceBundle EXIT (success)" );
      return Future.succeededFuture( serviceBundle );
    } );
  }
  
  /**
   * Verify and load ServiceBundle
  private Future<ServiceBundle> verifyAndLoadServiceBundle(ServiceBundle serviceBundle, 
                                                          SignedMessage signedMsg, 
                                                          byte[] domainBytes, 
                                                          String sourceServiceId)
  {
    Map<Long, DilithiumKey> verifyMap = serviceBundle.getVerifyKeys().get(sourceServiceId);
    long signerKeyId = signedMsg.getSignerKeyId();
    
    if (verifyMap == null || !verifyMap.containsKey(signerKeyId)) 
    {
      LOGGER.warn("Verification key {} for service {} not found - proceeding with load (bootstrapping)", 
                 signerKeyId, sourceServiceId);
      
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

    DilithiumKey signingKey = verifyMap.get(signerKeyId);
    return signedMsgProcessor.verifyWithKey(domainBytes, signedMsg.getSignature(), signingKey)
      .compose(verified -> 
      {
        if (!verified) 
        {
          LOGGER.warn("Signature verification failed for ServiceBundle from {}", sourceServiceId);
          return Future.failedFuture("Signature verification failed");
        }

        try 
        {
          keyCache.loadFromServiceBundle(serviceBundle);
          LOGGER.info("Successfully verified and loaded ServiceBundle from {}", sourceServiceId);
        } 
        catch (Exception e) 
        {
          LOGGER.error("Failed to load verified ServiceBundle", e);
          return Future.failedFuture(e);
        }
        
        return Future.succeededFuture(serviceBundle);
      });
  }
 */

  @Override
  public void stop(Promise<Void> stopPromise)
  {
    if (periodicKeyExchangeTimer != -1)
    {
      vertx.cancelTimer(periodicKeyExchangeTimer);
    }
    
    if (keyExchConsumer != null)
    {
      try 
      {
        keyExchConsumer.drain(Duration.ofSeconds(2));
        keyExchConsumer.unsubscribe();
      } 
      catch (Exception e) 
      {
        LOGGER.warn("Error closing key exchange subscription: {}", e.getMessage());
      }
    }
    
    if (workerExecutor != null)
    {
      workerExecutor.close();
    }
    
    stopPromise.complete();
    LOGGER.info("KeyExchangeVert stopped for service: {}", serviceId);
  }
}