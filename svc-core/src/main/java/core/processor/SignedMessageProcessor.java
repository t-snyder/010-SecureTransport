package core.processor;

import core.crypto.AesGcmHkdfCrypto;
import core.crypto.EncryptedData;
import core.exceptions.KeyMissingException;
import core.handler.KeySecretManager;
import core.model.DilithiumKey;
import core.model.service.TopicKey;
import core.service.DilithiumService;
import core.transport.SignedMessage;
import core.utils.KeyEpochUtil;
import core.utils.CAEpochUtil;

import io.vertx.core.Future;
import io.vertx.core.WorkerExecutor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;


/**
 * Generic processor for creating a SignedMessage for transport and decrypting and verifying on receipt.
 * 
 */
public class SignedMessageProcessor
{

  private static final Logger LOGGER = LoggerFactory.getLogger( SignedMessageProcessor.class );

  // Centralized prefix for shared-secret-generated encryptKeyId values.
  // Keep this in sync with any other code that generates/consumes shared-secret key ids.
  public static final String SHARED_SECRET_KEY_ID_PREFIX = "shared-secret-";

  private final WorkerExecutor   workerExecutor;
  private final KeySecretManager keyCache;
  private final AesGcmHkdfCrypto aesCrypto;
  private final DilithiumService signingManager;
//  private final KeyEpochUtil     keyEpochUtil = new KeyEpochUtil();
  private final CAEpochUtil      caEpochUtil  = new CAEpochUtil();

  private final ConcurrentHashMap<String, Future<Void>> pendingKeyFetches = new ConcurrentHashMap<>();
 
  public SignedMessageProcessor( WorkerExecutor workerExecutor, KeySecretManager keyCache )
  {
    this.workerExecutor = workerExecutor;
    this.keyCache       = keyCache;
    this.aesCrypto      = new AesGcmHkdfCrypto();
    this.signingManager = new DilithiumService( workerExecutor );
  }

   
  public Future<SignedMessage> createSignedMessage( String serviceId,   // service creating the message
                                                    byte[] objBytes,    // avro serialized domain obj
                                                    String messageType, // type code for message
                                                    String payloadType, // type code for payload - generally the same as messageType
                                                    String topic    )      // topic name the message will be sent on.
  {
    LOGGER.debug("Generating SignedMessage for service: {}", serviceId);

    // Get signing key (blocking)
    return workerExecutor.<DilithiumKey>executeBlocking( () -> 
    {
      long         currEpoch  = KeyEpochUtil.epochNumberForInstant( Instant.now() );
      DilithiumKey signingKey = keyCache.getSigningKey( currEpoch );
      if( signingKey == null )
      {
        String errMsg = "Signing key not found.";
        LOGGER.error( errMsg );
        throw new RuntimeException( errMsg );
      }
      return signingKey;
    })
    .compose( signingKey ->
       // Sign (async)
       signingManager.sign( objBytes, signingKey )
        .compose( signature ->
           // Step 3: encrypt (blocking)
           workerExecutor.<SignedMessage>executeBlocking( () -> 
           {
             return createSignedMessageWithTopicEncryption(serviceId, objBytes, messageType, payloadType, 
                 topic, signingKey, signature);
           })
         )
     )
    .onFailure( err -> 
     {
       String errMsg = "Failed to process bundle for service: " + serviceId + "; Error = " + err.getMessage();
       LOGGER.error(errMsg);
     });
  }

  /**
   * Create SignedMessage using shared secret encryption (new overload for key exchange).
   * 
   * @param serviceId     service creating the message
   * @param objBytes      avro serialized domain obj
   * @param messageType   type code for message
   * @param payloadType   type code for payload
   * @param topic         topic name the message will be sent on
   * @param sharedSecret  shared secret for encryption
   * @return Future<SignedMessage>
   */
  public Future<SignedMessage> createSignedMessage(String serviceId,
                                                   byte[] objBytes,
                                                   String messageType,
                                                   String payloadType,
                                                   String topic,
                                                   byte[] sharedSecret)
  {
    LOGGER.debug("Generating SignedMessage for service: {} using shared secret encryption", serviceId);

    // Get signing key (blocking)
    return workerExecutor.<DilithiumKey>executeBlocking( () -> 
    {
      DilithiumKey signingKey = keyCache.getSigningKey( KeyEpochUtil.epochNumberForInstant( Instant.now() ));
      if (signingKey == null)
      {
        String errMsg = "Signing key not found.";
        LOGGER.error(errMsg);
        throw new RuntimeException(errMsg);
      }
      return signingKey;
    })
    .compose(signingKey ->
       // Sign (async)
       signingManager.sign( objBytes, signingKey)
        .compose(signature ->
           // Encrypt using shared secret (blocking)
           workerExecutor.<SignedMessage>executeBlocking(() -> 
           {
             return createSignedMessageWithSharedSecretEncryption(serviceId, objBytes, messageType, payloadType,
                                                                  topic, signingKey, signature, sharedSecret);
           })
         )
     )
    .onFailure(err -> 
     {
       String errMsg = "Failed to process bundle for service: " + serviceId + "; Error = " + err.getMessage();
       LOGGER.error(errMsg);
     });
  }  
  
  /**
   * Helper method to create SignedMessage with topic-based encryption.
   */
  private SignedMessage createSignedMessageWithTopicEncryption(String serviceId,
                                                              byte[] objBytes,
                                                              String messageType,
                                                              String payloadType,
                                                              String topic,
                                                              DilithiumKey signingKey,
                                                              byte[] signature)
   throws Exception
  {
    long           keyEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
    List<TopicKey> keyList  = keyCache.getValidTopicKeysSorted( topic );

    TopicKey topicKey = null;
    for( TopicKey key : keyList ) 
    {
      if( keyEpoch == key.getEpochNumber()) 
      {
        topicKey = key;
        break;
      }
    }

    if (topicKey == null) 
    {
      LOGGER.error( "============================================================" );
      LOGGER.error( " Could not find topic Key for topic = " + topic + "; for epoch = " + keyEpoch );
      LOGGER.error( "Topic keys found for this topic are:"  );
      for( TopicKey key : keyList )
      {
        LOGGER.error( "Epoch = " + key.getEpochNumber() + " keyId " + key.getKeyId() );
      }

      Set<String> topics = keyCache.getAllTopicsWithKeys();
      LOGGER.error( "    ");
      LOGGER.error( "Topics supported by this service are:" );
      for( String nm : topics )
      {
        LOGGER.error( nm );
      }
      LOGGER.error( "============================================================" );
      
      String errMsg = "Could not obtain an encryption key for topic: " + topic;
      LOGGER.error(errMsg);
      throw new RuntimeException(errMsg);
    }
    
    EncryptedData encData = aesCrypto.encrypt( objBytes, topicKey.getKeyData() );
    if (encData == null || encData.getCiphertext() == null || encData.getCiphertext().length == 0)
    {
      throw new RuntimeException("Failed to encrypt for server: " + serviceId);
    }
    
    LOGGER.debug("Successfully generated and encrypted bundle for server: {} using topic key", serviceId);

    Instant now     = Instant.now();
    long    caEpoch = caEpochUtil.epochNumberForInstant( now );
    return new SignedMessage( serviceId + now.toString(),
                              messageType,
                              caEpoch,
                              keyEpoch,
                              serviceId,
                              signingKey.getEpochNumber(),
                              now,
                              signature,
                              topic,
                              topicKey.getKeyId(),
                              payloadType,
                              encData.serialize());
  } 

  /**
   * Helper method to create SignedMessage with shared secret encryption.
   */
  private SignedMessage createSignedMessageWithSharedSecretEncryption(String serviceId,
                                                                      byte[] objBytes,
                                                                      String messageType,
                                                                      String payloadType,
                                                                      String topic,
                                                                      DilithiumKey signingKey,
                                                                      byte[] signature,
                                                                      byte[] sharedSecret )
   throws Exception
  {
    if (sharedSecret == null || sharedSecret.length == 0)
    {
      String errMsg = "Shared secret cannot be null or empty";
      LOGGER.error(errMsg);
      throw new RuntimeException(errMsg);
    }

    EncryptedData encData = aesCrypto.encrypt(objBytes, sharedSecret);
    if (encData == null || encData.getCiphertext() == null || encData.getCiphertext().length == 0)
    {
      throw new RuntimeException("Failed to encrypt with shared secret for server: " + serviceId);
    }
    
    LOGGER.debug("Successfully generated and encrypted bundle for server: {} using shared secret", serviceId);

    // For shared secret encryption, we use a special key ID to indicate this is not a topic key
    String sharedSecretKeyId = SHARED_SECRET_KEY_ID_PREFIX + System.currentTimeMillis();

    Instant now      = Instant.now();
    long    keyEpoch = KeyEpochUtil.epochNumberForInstant( now );
    long    caEpoch  = caEpochUtil.epochNumberForInstant(  now );

    return new SignedMessage(serviceId + Instant.now().toString(),
                             messageType,
                             caEpoch,
                             keyEpoch,
                             serviceId,
                             signingKey.getEpochNumber(),
                             Instant.now(),
                             signature,
                             topic,
                             sharedSecretKeyId,
                             payloadType,
                             encData.serialize());
  }
  
  /**
   * Obtain, verify, decrypt, and deserialize the domain object from a
   * SignedMessage.
   */
  public Future<byte[]> obtainDomainObject( byte[] signedMsgBytes )
  {
    return workerExecutor.<Tuple3< byte[], SignedMessage, Long>> executeBlocking( () -> 
    {
      try
      {
        SignedMessage signedMsg = SignedMessage.deSerialize( signedMsgBytes );
        EncryptedData encData   = EncryptedData.deserialize( signedMsg.getPayload() );

        TopicKey encKey = keyCache.getTopicKey( signedMsg.getTopicName(), signedMsg.getEncryptKeyId() );
/**
        if( encKey == null )
        {
          String errMsg = "Encryption key could not be found for decryption. ServiceId = " + signedMsg.getSignerServiceId() + 
                                                                          "; Topic = " +     signedMsg.getTopicName() + 
                                                                          "; keyid = " +     signedMsg.getEncryptKeyId();
          LOGGER.error( errMsg );
          throw new Exception( errMsg );
        }
*/
        if( encKey == null ) 
        {
          LOGGER.error( "============================================================" );
          LOGGER.error( " Could not find topic Key for topic = " + signedMsg.getTopicName() + "; for keyId = " + signedMsg.getEncryptKeyId() );
          LOGGER.error( "Topic keys found for this topic are:"  );

          List<TopicKey> keyList = keyCache.getValidTopicKeysSorted( signedMsg.getTopicName() );
          for( TopicKey key : keyList )
          {
            LOGGER.error( "Epoch = " + key.getEpochNumber() + " keyId " + key.getKeyId() );
          }

          Set<String> topics = keyCache.getAllTopicsWithKeys();
          LOGGER.error( "    ");
          LOGGER.error( "Topics supported by this service are:" );
          for( String nm : topics )
          {
            LOGGER.error( nm );
          }
          LOGGER.error( "============================================================" );
          
          String errMsg = "Could not obtain an encryption key for topic: " + signedMsg.getTopicName();
          LOGGER.error(errMsg);
//          throw new RuntimeException(errMsg);
          throw new KeyMissingException( signedMsg.getSignerServiceId(), signedMsg.getTopicName(), signedMsg.getEncryptKeyId(),
              "Encryption key could not be found for decryption. Topic = " + signedMsg.getTopicName() + "; keyid = " + signedMsg.getEncryptKeyId());
       }

        byte[] domainBytes = aesCrypto.decrypt( encData, encKey.getKeyData() );

        return new Tuple3<>( domainBytes, signedMsg, signedMsg.getSignerKeyId() );
      } 
      catch( Exception e )
      {
        LOGGER.error( "Failed to process SignedMessage in background thread", e );
        throw new RuntimeException( e );
      }
    })
    .recover( err -> 
     {
       if( err instanceof KeyMissingException ) 
       {
         KeyMissingException kme = (KeyMissingException) err;
              
         LOGGER.info( "Key missing for topic '{}', keyId '{}' - attempting on-demand fetch", 
                      kme.getTopic(), kme.getKeyId());
              
         return fetchMissingKeyAndRetry(signedMsgBytes, kme);
       }
          
      // Other error - propagate
       return Future.failedFuture(err);
     })
    .compose( tuple -> 
     {
       byte[]        domainBytes  = tuple._1;
       SignedMessage signedMsg    = tuple._2;
       Long          signerKeyId  = tuple._3;

       return keyCache.getDilithiumPublicKey( signedMsg.getSignerServiceId(), signerKeyId )
          .compose( signingKey -> 
           {
             if( signingKey != null )
             {
               return signingManager.verify( domainBytes, signedMsg.getSignature(), signingKey )
                 .compose( verified -> 
                  {
                    if( !verified )
                    {
                      LOGGER.warn( "Signature verification failed for domain object from metadata" );
                      return Future.failedFuture( "Signature invalid" );
                    }
                    return Future.succeededFuture( domainBytes );
                  });
             } 
             else
             {
               LOGGER.warn( "No signing key found for domain object from metadata, skipping signature verification" );
               return Future.succeededFuture( domainBytes );
             }
           });
     });
  }
  
  /**
   * Obtains the decrypted domain bytes AND the parsed SignedMessage (no verification).
   * This is required when the caller wants to perform verification themselves using keys
   * contained within the domain object (e.g. ServiceBundle carrying signing keys).
   * 
   * @param signedMsgBytes serialized SignedMessage
   * @param encKey encryption key to use for decryption
   * @return Future<Tuple3<byte[], SignedMessage, String>> tuple of (domainBytes, SignedMessage, signerKeyId)
   */
  public Future<Tuple3<byte[], SignedMessage, Long>> obtainDomainObject(byte[] signedMsgBytes, byte[] encKey)
  {
    return workerExecutor.<Tuple3<byte[], SignedMessage, Long>>executeBlocking(() -> 
    {
      try
      {
        SignedMessage signedMsg = SignedMessage.deSerialize(signedMsgBytes);
        EncryptedData encData   = EncryptedData.deserialize(signedMsg.getPayload());

        if( encKey == null )
        {
          String errMsg = "Encryption key could not be found for decryption.";
          LOGGER.error(errMsg);
          throw new Exception(errMsg);
        }

        byte[] domainBytes = aesCrypto.decrypt(encData, encKey);

        return new Tuple3<>(domainBytes, signedMsg, signedMsg.getSignerKeyId());
      } 
      catch (Exception e)
      {
        LOGGER.error("Failed to process SignedMessage in background thread", e);
        throw new RuntimeException(e);
      }
    });
  } 
  
  private Future<Tuple3<byte[], SignedMessage, Long>> fetchMissingKeyAndRetry( byte[] signedMsgBytes, KeyMissingException kme )
  {

    // Extract epoch from keyId (e.g., "gatekeeper.responder-epoch-1957385")
    long missingEpoch = extractEpochFromKeyId( kme.getKeyId() );
    if( missingEpoch < 0 )
    {
      LOGGER.error( "Could not extract epoch from keyId: {}", kme.getKeyId() );
      return Future.failedFuture( kme );
    }

    // Determine which service's ServiceBundle we need
    // For topic keys, we need the ServiceBundle for the service that produces
    // to this topic
    // This is typically the signerServiceId from the message
    String targetServiceId = kme.getServiceId();

    LOGGER.info( "Attempting to fetch ServiceBundle: service='{}', epoch={}", targetServiceId, missingEpoch );

    // Check if already fetching this key to avoid duplicate requests
    String fetchKey = targetServiceId + ":" + missingEpoch;

    // Get or create fetch future
    Future<Void> fetchFuture = pendingKeyFetches.computeIfAbsent( fetchKey, k -> 
    {
      LOGGER.info( "Initiating ServiceBundle fetch for key '{}'", k );
      return keyCache.loadServiceBundleForEpoch( targetServiceId, missingEpoch ).onComplete( ar -> {
        // Remove from pending map when complete
        pendingKeyFetches.remove( k );

        if( ar.succeeded() )
        {
          LOGGER.info( "✅ ServiceBundle fetch successful for key '{}'", k );
        }
        else
        {
          LOGGER.error( "❌ ServiceBundle fetch failed for key '{}': {}", k, ar.cause().getMessage() );
        }
      } );
    } );

    // Wait for fetch to complete, then retry decryption
    return fetchFuture.compose( v -> {
      LOGGER.info( "Retrying decryption after ServiceBundle fetch" );

      // Retry the decryption with newly loaded keys
      return workerExecutor.<Tuple3<byte[], SignedMessage, Long>> executeBlocking( () -> {
        try
        {
          SignedMessage signedMsg = SignedMessage.deSerialize( signedMsgBytes );
          EncryptedData encData = EncryptedData.deserialize( signedMsg.getPayload() );

          // Try to get encryption key again
          TopicKey encKey = keyCache.getTopicKey( signedMsg.getTopicName(), signedMsg.getEncryptKeyId() );

          if( encKey == null )
          {
            // Still not found after fetch - log detailed error
            LOGGER.error( "============================================================" );
            LOGGER.error( "Key STILL not found after ServiceBundle fetch!" );
            LOGGER.error( "Service: {}, Topic: {}, KeyId: {}, Epoch: {}", targetServiceId, kme.getTopic(), kme.getKeyId(), missingEpoch );
            LOGGER.error( "============================================================" );

            throw new KeyMissingException( targetServiceId, kme.getTopic(), kme.getKeyId(), "Key not found even after ServiceBundle fetch - may not exist in Vault" );
          }

          // Decrypt with newly loaded key
          byte[] domainBytes = aesCrypto.decrypt( encData, encKey.getKeyData() );

          LOGGER.info( "✅ Decryption successful after on-demand key fetch" );

          return new Tuple3<>( domainBytes, signedMsg, signedMsg.getSignerKeyId() );

        }
        catch( Exception e )
        {
          LOGGER.error( "Retry decryption failed: {}", e.getMessage(), e );
          throw new RuntimeException( e );
        }
      } );
    } );
  }

  /**
   * Extract epoch number from keyId string
   */
  private long extractEpochFromKeyId( String keyId )
  {
    if( keyId == null || !keyId.contains( "-epoch-" ) )
    {
      return -1;
    }

    try
    {
      int lastDash = keyId.lastIndexOf( '-' );
      String epochStr = keyId.substring( lastDash + 1 );
      return Long.parseLong( epochStr );
    }
    catch( Exception e )
    {
      LOGGER.debug( "Could not extract epoch from keyId '{}': {}", keyId, e.getMessage() );
      return -1;
    }
  }
  
  /**
   * Public wrapper to verify a domain's signature using a provided DilithiumKey.
   * Returns the underlying signingManager.verify Future so callers can compose on it.
   */
  public Future<Boolean> verifyWithKey(byte[] domainBytes, byte[] signature, DilithiumKey signingKey)
  {
    return signingManager.verify(domainBytes, signature, signingKey);
  }


  /**
   * Common signature verification logic used by both obtainDomainObject methods.
  private Future<byte[]> verifySignatureAndReturnDomain(Tuple3<byte[], SignedMessage, Long> tuple)
  {
    byte[]        domainBytes = tuple._1;
    SignedMessage signedMsg   = tuple._2;
    Long          signerKeyId = tuple._3;

    return keyCache.getDilithiumPublicKey(signedMsg.getSignerServiceId(), signerKeyId)
        .compose(signingKey -> 
        {
          if (signingKey != null)
          {
            return signingManager.verify(domainBytes, signedMsg.getSignature(), signingKey)
                .compose(verified -> 
                {
                  if (!verified)
                  {
                    LOGGER.warn("Signature verification failed for domain object from metadata");
                    return Future.failedFuture("Signature invalid");
                  }
                  return Future.succeededFuture(domainBytes);
                });
          } 
          else
          {
            LOGGER.warn("No signing key found for domain object from metadata, skipping signature verification");
            return Future.succeededFuture(domainBytes);
          }
        });
  }
   */

  /**
   * Tuple3 utility for intermediate results.
   */
  private static class Tuple3<A, B, C>
  {
    public final A _1;
    public final B _2;
    public final C _3;

    public Tuple3(A a, B b, C c)
    {
      this._1 = a;
      this._2 = b;
      this._3 = c;
    }
  }}