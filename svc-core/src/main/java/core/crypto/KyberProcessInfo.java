package core.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.time.Instant;

public class KyberProcessInfo implements Serializable
{
  private static final long serialVersionUID = -2215389761069274551L;

  private String    sourceSvcId  = null;  // Initiator service id
  private String    targetSvcId  = null;  // Responder service id
  private KeyPair   keyPair      = null;  // Initiator generated key pair
  private byte[]    sharedSecret = null;  // Used to encrypt and decrypt between initiator and responder services.
  private Instant   createTime   = null;
  private Instant   expiryTime   = null;  // Time shared secret expires.
  
  
  /**
   * Constructor for initiator which generates a new KeyPair
 
   * @throws InvalidAlgorithmParameterException 
   * @throws NoSuchProviderException 
   * @throws NoSuchAlgorithmException 
   */
  public KyberProcessInfo( String sourceSvcId, String targetSvcId, Instant createTime, Instant expiryTime ) 
   throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
  {
    this.sourceSvcId = sourceSvcId;
    this.targetSvcId = targetSvcId;
    this.keyPair     = KyberKEMCrypto.generateKeyPair();
    this.createTime  = createTime;
    this.expiryTime  = expiryTime;
  }
  
  /**
   * Constructor for Initiator with pregenerated keypair
   * @param kyberKeyPair
   */
  public KyberProcessInfo( String sourceSvcId, String targetSvcId, KeyPair kyberKeyPair, Instant createTime, Instant expiryTime )
  {
    this.sourceSvcId = sourceSvcId;
    this.targetSvcId = targetSvcId;
    this.keyPair     = kyberKeyPair;
    this.createTime  = createTime;
    this.expiryTime  = expiryTime;
  }

  public String  getSourceSvcId()  { return sourceSvcId;  }
  public String  getTargetSvcId()  { return targetSvcId;  }
  public KeyPair getKeyPair()      { return keyPair;      }
  public byte[]  getSharedSecret() { return sharedSecret; }
  public Instant getCreateTime()   { return createTime;   }
  public Instant getExpiryTime()   { return expiryTime;   }

  public void setSharedSecret( byte[] keyBytes ) 
  {
    this.sharedSecret = keyBytes;
  }

  // Convenience Methods 
  public PublicKey getPublicKey() 
  {
    if( keyPair == null )
      return null;
    
    return keyPair.getPublic(); 
  }
  
  public PrivateKey getPrivateKey() 
  {
    if( keyPair == null )
      return null;
    
    return keyPair.getPrivate(); 
  }

/**
  public SecretKey getSecretKey() 
  { 
    return secretKey; 
  }
**/  

  public byte[] getPublicKeyEncoded()  
  { 
    if( keyPair != null )
      return KyberKEMCrypto.encodePublicKey(  keyPair.getPublic() );
    
    return null;
  }
  
  public byte[] getPrivateKeyEncoded() 
  { 
    if( keyPair != null )
      return KyberKEMCrypto.encodePrivateKey( keyPair.getPrivate()); 
    
    return null;
  }
  
  public static byte[] serialize( KyberProcessInfo key )
   throws IOException
  {
    try( ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream    objectOutputStream    = new ObjectOutputStream( byteArrayOutputStream )) 
    {
      objectOutputStream.writeObject( key );
      return byteArrayOutputStream.toByteArray();
    }
  }
  
  public static KyberProcessInfo deSerialize( byte[] keyBytes )
   throws IOException, ClassNotFoundException
  {
    try( ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream( keyBytes );
         ObjectInputStream    objectInputStream    = new ObjectInputStream(byteArrayInputStream) ) 
    {
      return (KyberProcessInfo) objectInputStream.readObject();
    }
  }
}
