/**
 * The inspiration for this code (and much of the code) was obtained from 
 * CRYSTALS Kyber for Post-Quantum Hybrid Encryption with Java
 * by Udara Pathum
 *
 * https://medium.com/@hwupathum/using-crystals-kyber-kem-for-hybrid-encryption-with-java-0ab6c70d41fc
 */

package core.crypto;


import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

//import javax.crypto.Cipher;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.KeyGenerator;
//import javax.crypto.spec.SecretKeySpec;
//import javax.crypto.spec.GCMParameterSpec;


/**
 * This code is used by both the Server and the client. It is performed in the
 * following steps. 
 * 
 * 1. The client ( pulsarWatcher ) generates a Kyber keypair using the generateKeyPair( int securityLevel ) method. 
 * 
 * 2. The client ( pulsarWatcher ) sends the publicKey to the Server ( metadataSevc ). This is external to this class.
 * 3. The server ( metadataSvc ) uses the publicKey to generate a shared secret (AES-256) and encapsulate it. 
 * 4. The server ( metadataSvc ) sends the encapsulated key back to the client ( pulsarWatcher ). External to this class. 
 * 5. The client ( pulsarWatcher ) extracts the encapsulated key into a SecretKeyWithEncapsulation using generateSecretKeyReciever().
 */
public class KyberKEMCrypto
{
  public static final AlgorithmParameterSpec KEM_PARAMETER_SPEC = KyberParameterSpec.kyber1024;
  private static final String PROVIDER             = "BCPQC";
  private static final String KEM_ALGORITHM        = "Kyber";
//  private static final String ENCRYPTION_ALGORITHM = "AES";
//  private static final String CIPHER_TYPE          = "AES/GCM/NoPadding"; 
  private static final int    GCM_TAG_LENGTH       = 16; // 128 bits
  private static final int    GCM_IV_LENGTH        = 12;
  private static final int    HKDF_SALT_LENGTH     = 32;
  private static final int    AES_KEY_LENGTH       = 32; // 256 bits
  private static final String HKDF_INFO            = "Kyber-HKDF-AES-2024";

  static
  {
    // Register Bouncy Castle providers if not already registered
    if( Security.getProvider( "BC" ) == null )
    {
      Security.addProvider( new BouncyCastleProvider() );
    }
    if( Security.getProvider( "BCPQC" ) == null )
    {
      Security.addProvider( new BouncyCastlePQCProvider() );
    }
  }

  /**
   * Generates a Kyber (ML-KEM) key pair.
   * 
   * @param securityLevel
   *          Security level: 512, 768, or 1024
   * @return A new Kyber KeyPair
   */
  public static KeyPair generateKeyPair() 
   throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
  {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( KEM_ALGORITHM, PROVIDER );
    keyPairGenerator.initialize( KEM_PARAMETER_SPEC, new SecureRandom() );

    return keyPairGenerator.generateKeyPair();
  }

  public static SecretKeyWithEncapsulation generateSecretKeyResponder( PublicKey publicKey ) 
   throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
  {
    KeyGenerator    keyGenerator    = KeyGenerator.getInstance( KEM_ALGORITHM, PROVIDER );
    KEMGenerateSpec kemGenerateSpec = new KEMGenerateSpec( publicKey, "Secret", 256 );

    keyGenerator.init( kemGenerateSpec );

    return (SecretKeyWithEncapsulation)keyGenerator.generateKey();
  }

  public static byte[] generateSecretKeyInitiator( PrivateKey privateKey, byte[] encapsulation ) 
   throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
  {
    KEMExtractSpec kemExtractSpec = new KEMExtractSpec( privateKey, encapsulation, "Secret", 256 );
    KeyGenerator   keyGenerator   = KeyGenerator.getInstance( KEM_ALGORITHM, PROVIDER );

    keyGenerator.init( kemExtractSpec );
    
    SecretKeyWithEncapsulation result = (SecretKeyWithEncapsulation)keyGenerator.generateKey();
    return result.getEncoded();
  }

  /**
   * Derive a session AES-256 key from a Kyber shared secret, using salt and info.
   */
  private static byte[] hkdfDeriveAesKey(byte[] sharedSecret, byte[] salt, String info) 
  {
    HKDFBytesGenerator hkdf   = new HKDFBytesGenerator( new SHA256Digest() );
    HKDFParameters     params = new HKDFParameters( sharedSecret, salt, info.getBytes( StandardCharsets.UTF_8 ));
    hkdf.init(params);

    byte[] aesKey = new byte[AES_KEY_LENGTH];
    hkdf.generateBytes( aesKey, 0, aesKey.length );
    return aesKey;
  }

  /**
   * Encrypts plaintext using AES-256-GCM with a key derived from the Kyber shared secret using HKDF.
   * Returns an EncryptedData object containing all necessary components (salt, iv, ciphertext, tag).
   */
  public static EncryptedData encryptWithHKDF( String plainText, byte[] sharedSecret ) 
   throws Exception
  {
    SecureRandom random = new SecureRandom();
    byte[]       salt   = new byte[HKDF_SALT_LENGTH];
    byte[]       iv     = new byte[GCM_IV_LENGTH];
    random.nextBytes(salt);
    random.nextBytes(iv);

    byte[] aesKey = hkdfDeriveAesKey( sharedSecret, salt, HKDF_INFO );

    try 
    {
      // Use BouncyCastle lightweight API for compatibility with EncryptedData
      GCMModeCipher  cipher = GCMBlockCipher.newInstance(new AESLightEngine());
      AEADParameters params = new AEADParameters( new KeyParameter(aesKey), GCM_TAG_LENGTH * 8, iv );
      cipher.init( true, params );

      byte[] plaintextBytes = plainText.getBytes(StandardCharsets.UTF_8);
      byte[] output         = new byte[cipher.getOutputSize(plaintextBytes.length)];
      int    len            = cipher.processBytes( plaintextBytes, 0, plaintextBytes.length, output, 0 );
      len += cipher.doFinal( output, len );

      byte[] ciphertext = Arrays.copyOf(      output, len - GCM_TAG_LENGTH      );
      byte[] tag        = Arrays.copyOfRange( output, len - GCM_TAG_LENGTH, len );

      return new EncryptedData( salt, iv, ciphertext, tag );
    } 
    finally 
    {
      Arrays.fill( aesKey, (byte)0 );
    }
  }

  /**
   * Decrypts an EncryptedData object using a key derived from the Kyber shared secret via HKDF.
   * Returns the plaintext string.
   */
  public static byte[] decryptWithHKDF( EncryptedData encryptedData, byte[] sharedSecret ) 
   throws Exception
  {
    byte[] aesKey = hkdfDeriveAesKey( sharedSecret, encryptedData.getSalt(), HKDF_INFO );

    try 
    {
      GCMModeCipher  cipher = GCMBlockCipher.newInstance( new AESLightEngine() );
      AEADParameters params = new AEADParameters( new KeyParameter(aesKey), GCM_TAG_LENGTH * 8, encryptedData.getIv());
      cipher.init(false, params);

      byte[] input = new byte[encryptedData.getCiphertext().length + encryptedData.getTag().length];
      System.arraycopy( encryptedData.getCiphertext(), 0, input, 0, encryptedData.getCiphertext().length);
      System.arraycopy( encryptedData.getTag(),        0, input, encryptedData.getCiphertext().length, encryptedData.getTag().length);

      byte[] output = new byte[cipher.getOutputSize(input.length)];
      int    len = cipher.processBytes(input, 0, input.length, output, 0);
      len += cipher.doFinal(output, len);

      return Arrays.copyOf( output, len );
    } 
    finally 
    {
      Arrays.fill( aesKey, (byte)0 );
    }
  }
  
  /**
   * Encrypt with AES/GCM
   * @param plainText
   * @param key  - Obtained via SecretKeyWtihEncapsulation.getEncoded() returned from method generateSecretKeySender()
   * @return
   * @throws Exception
  public static String encrypt( String plainText, byte[] key ) 
   throws Exception
  {
    SecretKeySpec secretKey = new SecretKeySpec( key, ENCRYPTION_ALGORITHM );
    Cipher        cipher    = Cipher.getInstance( CIPHER_TYPE );
    SecureRandom  random    = new SecureRandom();
    byte[]        iv        = new byte[12]; // GCM requires a 12-byte IV
   
    random.nextBytes(iv);
    GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); // 128-bit authentication tag
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

    // Encrypt the plaintext
    byte[] ciphertext = cipher.doFinal( plainText.getBytes() );
  
    // Combine IV and ciphertext
    byte[] encryptedBytes = new byte[iv.length + ciphertext.length];
    System.arraycopy( iv, 0, encryptedBytes, 0, iv.length);
    System.arraycopy( ciphertext, 0, encryptedBytes, iv.length, ciphertext.length);

    return Base64.getEncoder().encodeToString( encryptedBytes );
  }
*/

  /**
   * 
   * @param encryptedText
   * @param key - Obtained via SecretKeyWtihEncapsulation.getEncoded() returned from method generateSecretKeyReceiver()
   * @return
   * @throws Exception
  public static String decrypt( String encryptedText, byte[] key ) 
   throws Exception
  {
    SecretKeySpec secretKey = new SecretKeySpec( key, ENCRYPTION_ALGORITHM );
    Cipher cipher = Cipher.getInstance( MODE_PADDING );
    cipher.init( Cipher.DECRYPT_MODE, secretKey );
    byte[] decodedBytes = Base64.getDecoder().decode( encryptedText );
    byte[] decryptedBytes = cipher.doFinal( decodedBytes );
    return new String( decryptedBytes );
  }
   */

/*  
  public static byte[] decrypt(byte[] encryptedData, byte[] keyBytes ) 
   throws Exception 
  {
    SecretKeySpec secretKey = new SecretKeySpec( keyBytes, ENCRYPTION_ALGORITHM );
    Cipher        cipher    = Cipher.getInstance( CIPHER_TYPE );

    // Extract IV from the encrypted data
    byte[] iv = new byte[12];
    System.arraycopy( encryptedData, 0, iv, 0, iv.length );

    // Extract ciphertext from the encrypted data
    byte[] ciphertext = new byte[encryptedData.length - iv.length];
    System.arraycopy( encryptedData, iv.length, ciphertext, 0, ciphertext.length );

    GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
    cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

    // Decrypt the ciphertext
    return cipher.doFinal( ciphertext );
  }
*/
 
  public static byte[] encodePublicKey( PublicKey publicKey )
  {
//    return Base64.getEncoder().encodeToString( publicKey.getEncoded() );
    return Base64.getEncoder().encode( publicKey.getEncoded() );
  }

  public static byte[] encodePrivateKey( PrivateKey privateKey )
  {
    return Base64.getEncoder().encode( privateKey.getEncoded() );
  }
  
  public static PublicKey decodePublicKey( byte[] encodedKey ) throws Exception
  {
    byte[]             keyBytes   = Base64.getDecoder().decode( encodedKey );
    KeyFactory         keyFactory = KeyFactory.getInstance( KEM_ALGORITHM, PROVIDER );
    X509EncodedKeySpec keySpec    = new X509EncodedKeySpec( keyBytes );
 
    return keyFactory.generatePublic( keySpec );
  }

  public static PrivateKey decodePrivateKey( byte[] encodedKey ) throws Exception
  {
    byte[]              keyBytes   = Base64.getDecoder().decode( encodedKey );
    KeyFactory          keyFactory = KeyFactory.getInstance( KEM_ALGORITHM, PROVIDER );
    PKCS8EncodedKeySpec keySpec    = new PKCS8EncodedKeySpec( keyBytes );
 
    return keyFactory.generatePrivate( keySpec );
  }
  
  public static SecretKeyWithEncapsulation processKyberExchangeRequest( byte[] keyData )
   throws Exception
  {
//    byte[] decodedBytes  = Base64.getDecoder().decode( data );
       
    PublicKey                  publicKey     = KyberKEMCrypto.decodePublicKey( keyData );
    SecretKeyWithEncapsulation encapsulation = KyberKEMCrypto.generateSecretKeyResponder( publicKey );
       
    return encapsulation;
  }
}