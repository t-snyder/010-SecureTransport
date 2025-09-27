package core.model;


import io.fabric8.kubernetes.api.model.Secret;

import java.time.Instant;
//import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.crypto.AesGcmHkdfCrypto;
import core.crypto.EncryptedData;

/**
 * Factory class for creating certificate messages from Kubernetes secrets. This
 * class handles the extraction of certificate data from K8s secrets and
 * creation of CertificateMessage objects.
 */
public class CertificateMessageFactory
{

  private static final Logger LOGGER = LoggerFactory.getLogger( CertificateMessageFactory.class );

  // Secret key for encryption 
  private final byte[]     encryptionKey;
  private AesGcmHkdfCrypto aesHandler    = null;
  
  
  /**
   * Constructor
   * 
   * @param encryptionKey
   *          The key to use for message encryption
   */
  public CertificateMessageFactory( byte[] encryptionKey )
  {
    if( encryptionKey == null )
    {
      String errMsg = "CertificateMessageFactory.constructor - Encryption key cannot be null or empty";
      LOGGER.info( errMsg );
      throw new IllegalArgumentException( errMsg );
    }
 
    this.encryptionKey = encryptionKey;
    this.aesHandler    = new AesGcmHkdfCrypto();
  }

  /**
   * Creates an encrypted message from a Kubernetes secret
   * 
   * @param secret
   *          The Kubernetes secret containing certificate data
   * @param eventType
   *          The type of event (INITIAL, ADDED, MODIFIED, DELETED)
   * @return Encrypted message as byte array
   * @throws Exception
   *           If message creation fails
   */
  public byte[] createMsgFromSecret( Secret secret, String eventType, String serviceId ) 
    throws Exception
  {
    if( secret == null || secret.getMetadata() == null )
    {
      throw new IllegalArgumentException( "Secret cannot be null" );
    }

    Map<String, String> data = secret.getData();
    if( data == null )
    {
      throw new IllegalArgumentException( "Secret data is null" );
    }

    // Extract certificate data from the secret
    String caCert  = extractCertificate( data, "ca.crt" );
    String tlsCert = extractCertificate( data, "tls.crt" );

    if( tlsCert == null )
    {
      LOGGER.warn( "TLS certificate not found in secret: {}", secret.getMetadata().getName() );
    }

    // Create the certificate message
    CertificateMessage certMsg      = new CertificateMessage( UUID.randomUUID().toString(), Instant.now().toEpochMilli(), eventType, serviceId, caCert, tlsCert );
    byte[]             certMsgBytes = CertificateMessage.serialize( certMsg );

    LOGGER.info( "CertificateMessageFactory.createMsgFromSecret. encryptionKey = " + encryptionKey );
   
    EncryptedData encData = aesHandler.encrypt( certMsgBytes, encryptionKey );
    return encData.serialize();
  }

  /**
   * Helper method to extract certificate data from secret data map
   * 
   * @param data
   *          The secret data map
   * @param key
   *          The key for the certificate (e.g., "ca.crt", "tls.crt")
   * @return The certificate data as a string, or null if not found
   */
  private String extractCertificate( Map<String, String> data, String key )
  {
    if( !data.containsKey( key ) )
    {
      LOGGER.debug( "Certificate key '{}' not found in secret data", key );
      return null;
    }

    // The certificate is already Base64 encoded in the Secret
    // We return it as is since we'll use it encoded in our message
    return data.get( key );
  }

  /**
   * Creates an initial certificate message
   * 

   * @param secret
   *          The Kubernetes secret
   * @return Encrypted message as byte array
   * @throws Exception
   *           If message creation fails
   */
  public byte[] createInitialMessage( Secret secret, String requestingServiceId ) 
    throws Exception
  {
    return createMsgFromSecret( secret, "INITIAL", requestingServiceId );
  }

  /**
   * Creates an added certificate message
   * 
   * @param secret
   *          The Kubernetes secret
   * @return Encrypted message as byte array
   * @throws Exception
   *           If message creation fails
   */
  public byte[] createAddedMessage( Secret secret, String requestingServiceId )
   throws Exception
  {
    return createMsgFromSecret( secret, "ADDED", requestingServiceId );
  }

  /**
   * Creates a modified certificate message
   * 
   * @param secret
   *          The Kubernetes secret
   * @return Encrypted message as byte array
   * @throws Exception
   *           If message creation fails
   */
  public byte[] createModifiedMessage( Secret secret, String requestingServiceId )
   throws Exception
  {
    return createMsgFromSecret( secret, "MODIFIED", requestingServiceId );
  }

  /**
   * Creates a deleted certificate message
   * 
   * @param secret
   *          The Kubernetes secret
   * @return Encrypted message as byte array
   * @throws Exception
   *           If message creation fails
   */
  public byte[] createDeletedMessage( Secret secret, String requestingServiceId ) 
   throws Exception
  {
    return createMsgFromSecret( secret, "DELETED", requestingServiceId );
  }
 
}