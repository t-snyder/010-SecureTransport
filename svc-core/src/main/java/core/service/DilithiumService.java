package core.service;


import io.vertx.core.Future;
import io.vertx.core.WorkerExecutor;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.model.DilithiumKey;

/**
 * High-level service interface for Dilithium operations Now uses the
 * DilithiumKeyManager abstraction to avoid circular dependencies
 */
public class DilithiumService
{
  private static final Logger LOGGER         = LoggerFactory.getLogger( DilithiumService.class );
  private static final String HASH_ALGORITHM = "SHA3-512";

  private final WorkerExecutor workerExecutor;

  public DilithiumService( WorkerExecutor workerExecutor )
  {
    this.workerExecutor = workerExecutor;
  }

  /**
   * Sign data with automatic hashing
   */
  public Future<byte[]> sign( byte[] data, DilithiumKey key )
  {
    if( key == null || !key.canSign() )
    {
      return Future.failedFuture( "Key cannot sign - no private key" );
    }

    return workerExecutor.executeBlocking( () -> 
    {
      try
      {
        // Hash the data first
        MessageDigest digest     = MessageDigest.getInstance( HASH_ALGORITHM );
        byte[]        hashedData = digest.digest( data );

        // Sign the hash
        DilithiumSigner               signer     = new DilithiumSigner();
        DilithiumPrivateKeyParameters privParams = ( (DilithiumPrivateKey)key.getPrivateKey() ).getKeyParams();

        signer.init( true, privParams );
        return signer.generateSignature( hashedData );
      } 
      catch( Exception e )
      {
        LOGGER.error( "Signing failed: {}", e.getMessage(), e );
        throw new RuntimeException( e );
      }
    });
  }

  /**
   * Verify signature with automatic hashing
   */
  public Future<Boolean> verify( byte[] data, byte[] signature, DilithiumKey key )
  {
    return workerExecutor.executeBlocking( () -> 
    {
      try
      {
        // Hash the data first
        MessageDigest digest     = MessageDigest.getInstance( HASH_ALGORITHM );
        byte[]        hashedData = digest.digest( data );

        // Verify the signature
        DilithiumSigner              signer    = new DilithiumSigner();
        DilithiumPublicKeyParameters pubParams = ( (DilithiumPublicKey)key.getPublicKey() ).getKeyParams();

        signer.init( false, pubParams );
        return signer.verifySignature( hashedData, signature );
      } 
      catch( Exception e )
      {
        LOGGER.warn( "Verification failed: {}", e.getMessage() );
        return false;
      }
    });
  }


  // Inner classes for standard Java security interfaces
  public static class DilithiumPublicKey implements PublicKey
  {
    private static final long serialVersionUID = -3623171863256889106L;
    private final DilithiumPublicKeyParameters keyParams;

    public DilithiumPublicKey( DilithiumPublicKeyParameters keyParams )
    {
      this.keyParams = keyParams;
    }

    public DilithiumPublicKeyParameters getKeyParams()
    {
      return keyParams;
    }

    @Override
    public String getAlgorithm()
    {
      return "DILITHIUM";
    }

    @Override
    public String getFormat()
    {
      return "X.509";
    }

    @Override
    public byte[] getEncoded()
    {
      return keyParams.getEncoded();
    }
  }

  public static class DilithiumPrivateKey implements PrivateKey
  {
    private static final long serialVersionUID = -2687533421084353747L;
    private final DilithiumPrivateKeyParameters keyParams;

    public DilithiumPrivateKey( DilithiumPrivateKeyParameters keyParams )
    {
      this.keyParams = keyParams;
    }

    public DilithiumPrivateKeyParameters getKeyParams()
    {
      return keyParams;
    }

    @Override
    public String getAlgorithm()
    {
      return "DILITHIUM";
    }

    @Override
    public String getFormat()
    {
      return "PKCS#8";
    }

    @Override
    public byte[] getEncoded()
    {
      return keyParams.getEncoded();
    }
  }
}