package core.crypto;


import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AesGcmHkdfCrypto
{
  private static final Logger LOGGER = LoggerFactory.getLogger( AesGcmHkdfCrypto.class );

  private static final int AES_KEY_LENGTH = 32; // 256 bits
  private static final int GCM_IV_LENGTH = 12; // 96 bits
  private static final int GCM_TAG_LENGTH = 16; // 128 bits
  private static final int HKDF_SALT_LENGTH = 32;
  private static final String HKDF_INFO = "AES-GCM-HKDF-2024";

  static
  {
    Security.addProvider( new BouncyCastleProvider() );
  }

  private final GCMModeCipher encryptCipher;
  private final GCMModeCipher decryptCipher;
  private final HKDFBytesGenerator hkdfGenerator;
  private SecureRandom secureRandom;

  public AesGcmHkdfCrypto()
  {
    this.encryptCipher = GCMBlockCipher.newInstance( new AESLightEngine() );
    this.decryptCipher = GCMBlockCipher.newInstance( new AESLightEngine() );
    this.hkdfGenerator = new HKDFBytesGenerator( new SHA256Digest() );
    this.secureRandom = new SecureRandom();
  }

  public void rotateRandom()
  {
    this.secureRandom = new SecureRandom();
  }

  // Backwards-compatible overloads (no AAD)
  public EncryptedData encrypt( byte[] plaintext, byte[] sharedSecret ) throws Exception
  {
    return encrypt( plaintext, sharedSecret, null );
  }

  public byte[] decrypt( EncryptedData encryptedData, byte[] sharedSecret ) throws Exception
  {
    return decrypt( encryptedData, sharedSecret, null );
  }

  // New AAD-aware overloads
  public EncryptedData encrypt( byte[] plaintext, byte[] sharedSecret, byte[] aad ) 
   throws Exception
  {
    byte[] salt = new byte[HKDF_SALT_LENGTH];
    byte[] iv = new byte[GCM_IV_LENGTH];

    secureRandom.nextBytes( salt );
    secureRandom.nextBytes( iv );

    byte[] derivedKey = deriveKeyInstance( sharedSecret, salt, HKDF_INFO );

    try
    {
      AEADParameters parameters = new AEADParameters( new KeyParameter( derivedKey ), GCM_TAG_LENGTH * 8, iv );
      encryptCipher.init( true, parameters );

      if( aad != null && aad.length > 0 )
      {
        encryptCipher.processAADBytes( aad, 0, aad.length );
      }

      byte[] output = new byte[encryptCipher.getOutputSize( plaintext.length )];
      int len = encryptCipher.processBytes( plaintext, 0, plaintext.length, output, 0 );
      len += encryptCipher.doFinal( output, len );

      byte[] ciphertext = Arrays.copyOf( output, len - GCM_TAG_LENGTH );
      byte[] tag = Arrays.copyOfRange( output, len - GCM_TAG_LENGTH, len );

      return new EncryptedData( salt, iv, ciphertext, tag );

    } 
    finally
    {
      Arrays.fill( derivedKey, (byte)0 );
    }
  }

  public byte[] decrypt( EncryptedData encryptedData, byte[] sharedSecret, byte[] aad ) throws Exception
  {
    byte[] derivedKey = deriveKeyInstance( sharedSecret, encryptedData.getSalt(), HKDF_INFO );

    try
    {
      AEADParameters parameters = new AEADParameters( new KeyParameter( derivedKey ), GCM_TAG_LENGTH * 8, encryptedData.getIv() );
      decryptCipher.init( false, parameters );

      if( aad != null && aad.length > 0 )
      {
        decryptCipher.processAADBytes( aad, 0, aad.length );
      }

      byte[] input = new byte[encryptedData.getCiphertext().length + encryptedData.getTag().length];
      System.arraycopy( encryptedData.getCiphertext(), 0, input, 0, encryptedData.getCiphertext().length );
      System.arraycopy( encryptedData.getTag(), 0, input, encryptedData.getCiphertext().length, encryptedData.getTag().length );

      byte[] output = new byte[decryptCipher.getOutputSize( input.length )];
      int len = decryptCipher.processBytes( input, 0, input.length, output, 0 );
      len += decryptCipher.doFinal( output, len );

      return Arrays.copyOf( output, len );
    } 
    finally
    {
      Arrays.fill( derivedKey, (byte)0 );
    }
  }

  private byte[] deriveKeyInstance( byte[] sharedSecret, byte[] salt, String info )
  {
    HKDFParameters params = new HKDFParameters( sharedSecret, salt, info.getBytes() );
    hkdfGenerator.init( params );

    byte[] derivedKey = new byte[AES_KEY_LENGTH];
    hkdfGenerator.generateBytes( derivedKey, 0, AES_KEY_LENGTH );

    return derivedKey;
  }
}
