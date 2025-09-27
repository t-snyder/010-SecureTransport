package core.crypto;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * Single-sender symmetric ratchet per (topic, epochId, producerId). Provides
 * lightweight PFS without handshakes.
 */
public final class RatchetingTopicCipher
{
  private static final String HMAC = "HmacSHA256";

  public static final class State
  {
    public final String epochId;
    public final String producerId;
    public long counter; // next counter to use (sender) or last advanced to
                         // (receiver)
    private byte[] chainKey; // current chain key (erased as we move forward)

    public State(String epochId, String producerId, long counter, byte[] chainKey) {
      this.epochId    = Objects.requireNonNull(epochId, "epochId");
      this.producerId = Objects.requireNonNull(producerId, "producerId");
      this.counter    = counter;
      this.chainKey   = Objects.requireNonNull(chainKey, "chainKey");
    }
  }

  private RatchetingTopicCipher()
  {
  }

  // Seed per-producer ratchet from epoch root secret
  public static State initSender( String epochId, String producerId, byte[] epochRootSecret ) throws Exception
  {
    byte[] seed = hkdf( epochRootSecret, producerId.getBytes( StandardCharsets.UTF_8 ), "topic-ratchet-v1".getBytes( StandardCharsets.UTF_8 ), 32 );
    byte[] firstCk = kdf( seed, "ck" );
    zero( seed );
    return new State( epochId, producerId, 0L, firstCk );
  }

  // Seed receiver state deterministically like sender; set counter to 0
  // initially
  public static State initReceiver( String epochId, String producerId, byte[] epochRootSecret ) throws Exception
  {
    return initSender( epochId, producerId, epochRootSecret );
  }

  // Derive next message key and advance ratchet (sender)
  public static byte[] nextMessageKey( State s ) throws Exception
  {
    byte[] mk = kdf( s.chainKey, "mk" ); // 32-byte message key
    byte[] next = kdf( s.chainKey, "ck" );
    zero( s.chainKey );
    s.chainKey = next;
    s.counter++;
    return mk;
  }

  // Receiver advance from current counter to target counter (bounded by
  // maxSkip)
  // Returns null if targetCounter < current (replay)
  public static byte[] deriveMessageKey( State s, long targetCounter, int maxSkip ) throws Exception
  {
    if( targetCounter < s.counter )
      return null; // replay
    long delta = targetCounter - s.counter;
    if( delta > maxSkip )
      throw new IllegalStateException( "ratchet skip too large: " + delta );
    byte[] mk = null;
    for( long i = 0; i <= delta; i++ )
    {
      mk = kdf( s.chainKey, "mk" );
      byte[] next = kdf( s.chainKey, "ck" );
      zero( s.chainKey );
      s.chainKey = next;
      s.counter++;
    }
    return mk;
  }

  public static EncryptedData encryptMessage( AesGcmHkdfCrypto gcm, byte[] messageKey, byte[] plaintext, byte[] aad ) throws Exception
  {
    return gcm.encrypt( plaintext, messageKey, aad );
  }

  public static byte[] decryptMessage( AesGcmHkdfCrypto gcm, byte[] messageKey, EncryptedData ed, byte[] aad ) throws Exception
  {
    return gcm.decrypt( ed, messageKey, aad );
  }

  private static byte[] hkdf( byte[] ikm, byte[] salt, byte[] info, int len )
  {
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator( new SHA256Digest() );
    hkdf.init( new HKDFParameters( ikm, salt, info ) );
    byte[] out = new byte[len];
    hkdf.generateBytes( out, 0, len );
    return out;
  }

  private static byte[] kdf( byte[] key, String label ) throws Exception
  {
    Mac mac = Mac.getInstance( HMAC );
    mac.init( new SecretKeySpec( key, HMAC ) );
    return mac.doFinal( label.getBytes( StandardCharsets.UTF_8 ) ); // 32 bytes
                                                                    // with
                                                                    // SHA-256
  }

  private static void zero( byte[] b )
  {
    if( b != null )
      Arrays.fill( b, (byte)0 );
  }
}