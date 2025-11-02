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
  private static final Logger LOGGER = LoggerFactory.getLogger(AesGcmHkdfCrypto.class);

  private static final int AES_KEY_LENGTH = 32;   // 256 bits
  private static final int GCM_IV_LENGTH  = 12;   // 96 bits
  private static final int GCM_TAG_LENGTH = 16;   // 128 bits (bytes)
  private static final int HKDF_SALT_LENGTH = 32;
  private static final String HKDF_INFO = "AES-GCM-HKDF-2024";

  static
  {
    Security.addProvider( new BouncyCastleProvider() );
  }

  // SecureRandom is thread-safe in modern JDKs and OK to share.
  private volatile SecureRandom secureRandom = new SecureRandom();

  public AesGcmHkdfCrypto()
  {
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

  // AAD-aware overloads
  public EncryptedData encrypt( byte[] plaintext, byte[] sharedSecret, byte[] aad ) throws Exception
  {
    if( plaintext == null )
      throw new IllegalArgumentException( "plaintext cannot be null" );
    if( sharedSecret == null || sharedSecret.length == 0 )
      throw new IllegalArgumentException( "sharedSecret cannot be null/empty" );

    byte[] salt = new byte[HKDF_SALT_LENGTH];
    byte[] iv = new byte[GCM_IV_LENGTH];
    secureRandom.nextBytes( salt );
    secureRandom.nextBytes( iv );

    byte[] derivedKey = deriveKeyInstance( sharedSecret, salt, HKDF_INFO );
    try
    {
      // Create a fresh cipher per call to avoid reuse/thread-safety issues
      GCMModeCipher  gcm    = GCMBlockCipher.newInstance( new AESLightEngine() );
      AEADParameters params = new AEADParameters( new KeyParameter( derivedKey ), GCM_TAG_LENGTH * 8, iv );
      gcm.init( true, params );

      if( aad != null && aad.length > 0 )
      {
        gcm.processAADBytes( aad, 0, aad.length );
      }

      byte[] output = new byte[gcm.getOutputSize( plaintext.length )];
      int len = gcm.processBytes( plaintext, 0, plaintext.length, output, 0 );
      len += gcm.doFinal( output, len );

      // Split ciphertext and tag
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
    if( encryptedData == null )
      throw new IllegalArgumentException( "encryptedData cannot be null" );
    if( sharedSecret == null || sharedSecret.length == 0 )
      throw new IllegalArgumentException( "sharedSecret cannot be null/empty" );

    byte[] derivedKey = deriveKeyInstance( sharedSecret, encryptedData.getSalt(), HKDF_INFO );
    try
    {
      // Fresh cipher per call
      GCMModeCipher  gcm    = GCMBlockCipher.newInstance( new AESLightEngine() );
      AEADParameters params = new AEADParameters( new KeyParameter( derivedKey ), GCM_TAG_LENGTH * 8, encryptedData.getIv() );
      gcm.init( false, params );

      if( aad != null && aad.length > 0 )
      {
        gcm.processAADBytes( aad, 0, aad.length );
      }

      // Concatenate ciphertext + tag for decryption
      byte[] input = new byte[encryptedData.getCiphertext().length + encryptedData.getTag().length];
      System.arraycopy( encryptedData.getCiphertext(), 0, input, 0, encryptedData.getCiphertext().length );
      System.arraycopy( encryptedData.getTag(), 0, input, encryptedData.getCiphertext().length, encryptedData.getTag().length );

      byte[] output = new byte[gcm.getOutputSize( input.length )];
      int len = gcm.processBytes( input, 0, input.length, output, 0 );
      len += gcm.doFinal( output, len );

      return Arrays.copyOf( output, len );
    }
    finally
    {
      Arrays.fill( derivedKey, (byte)0 );
    }
  }

  private byte[] deriveKeyInstance( byte[] sharedSecret, byte[] salt, String info )
  {
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator( new SHA256Digest() );
    HKDFParameters params = new HKDFParameters( sharedSecret, salt, info.getBytes() );
    hkdf.init( params );

    byte[] derivedKey = new byte[AES_KEY_LENGTH];
    hkdf.generateBytes( derivedKey, 0, AES_KEY_LENGTH );
    return derivedKey;
  }
}