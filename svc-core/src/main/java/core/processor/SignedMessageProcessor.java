package core.processor;

import core.crypto.AesGcmHkdfCrypto;
import core.crypto.EncryptedData;
import core.handler.KeySecretManager;
import core.model.DilithiumKey;
import core.model.service.TopicKey;
import core.service.DilithiumService;
import core.transport.SignedMessage;
import core.utils.KeyEpochUtil;

import io.vertx.core.Future;
import io.vertx.core.WorkerExecutor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;


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
  private final KeyEpochUtil     epochUtil = new KeyEpochUtil();

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
    LOGGER.info("Generating SignedMessage for service: {}", serviceId);

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
    LOGGER.info("Generating SignedMessage for service: {} using shared secret encryption", serviceId);

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
    long keyEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
    List<TopicKey> keyList = keyCache.getValidTopicKeysSorted( topic );

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
      String errMsg = "Could not obtain an encryption key for topic: " + topic;
      LOGGER.error(errMsg);
      throw new RuntimeException(errMsg);
    }
    
    EncryptedData encData = aesCrypto.encrypt( objBytes, topicKey.getKeyData() );
    if (encData == null || encData.getCiphertext() == null || encData.getCiphertext().length == 0)
    {
      throw new RuntimeException("Failed to encrypt for server: " + serviceId);
    }
    
    LOGGER.info("Successfully generated and encrypted bundle for server: {} using topic key", serviceId);

    return new SignedMessage( serviceId + Instant.now().toString(),
                              messageType,
                              serviceId,
                              signingKey.getEpochNumber(),
                              Instant.now(),
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
    
    LOGGER.info("Successfully generated and encrypted bundle for server: {} using shared secret", serviceId);

    // For shared secret encryption, we use a special key ID to indicate this is not a topic key
    String sharedSecretKeyId = SHARED_SECRET_KEY_ID_PREFIX + System.currentTimeMillis();

    return new SignedMessage(serviceId + Instant.now().toString(),
                             messageType,
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
        SignedMessage signedMsg = SignedMessage.deserialize( signedMsgBytes );
        EncryptedData encData   = EncryptedData.deserialize( signedMsg.getPayload() );

        TopicKey encKey = keyCache.getTopicKey( signedMsg.getTopicName(), signedMsg.getEncryptKeyId() );
        if( encKey == null )
        {
          String errMsg = "Encryption key could not be found for decryption. ServiceId = " + signedMsg.getSignerServiceId() + 
                                                                          "; Topic = " +     signedMsg.getTopicName() + 
                                                                          "; keyid = " +     signedMsg.getEncryptKeyId();
          LOGGER.error( errMsg );
          throw new Exception( errMsg );
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
        SignedMessage signedMsg = SignedMessage.deserialize(signedMsgBytes);
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
   */
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