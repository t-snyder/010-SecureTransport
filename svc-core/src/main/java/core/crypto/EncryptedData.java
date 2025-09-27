package core.crypto;

import java.nio.ByteBuffer;

/**
 * Container for all components of an AEAD-encrypted message using HKDF-derived keys.
 * salt - for HKDF key derivation (transmitted with ciphertext)
 * iv   - for AES-GCM (transmitted with ciphertext)
 * ciphertext - the encrypted message
 * tag  - authentication tag from AES-GCM
 */
public final class EncryptedData
{
  private final byte[] salt;
  private final byte[] iv;
  private final byte[] ciphertext;
  private final byte[] tag;

  public EncryptedData( byte[] salt, byte[] iv, byte[] ciphertext, byte[] tag )
  {
    if( salt == null || iv == null || ciphertext == null || tag == null )
    {
      throw new IllegalArgumentException("EncryptedData -All attributes must be provided");
    }
    
    this.salt       = salt.clone();
    this.iv         = iv.clone();
    this.ciphertext = ciphertext.clone();
    this.tag        = tag.clone();
  }

  public byte[] getSalt() { return salt; }
  public byte[] getIv()   { return iv;   }
  public byte[] getCiphertext() { return ciphertext; }
  public byte[] getTag() {  return tag;  }

  /**
   * Serialize all components into a single byte array for transmission
   * Format: [salt_length][salt][iv_length][iv][tag_length][tag][ciphertext]
   */
  public byte[] serialize()
  {
    ByteBuffer buffer = ByteBuffer.allocate( 4 + salt.length + 
                                             4 + iv.length + 
                                             4 + tag.length + 
                                             ciphertext.length 
                                           );

    buffer.putInt( salt.length );
    buffer.put(    salt        );
    buffer.putInt( iv.length   );
    buffer.put(    iv          );
    buffer.putInt( tag.length  );
    buffer.put(    tag         );
    buffer.put(    ciphertext  );

    return buffer.array();
  }

  /**
   * Deserialize byte array back into EncryptedData
   */
  public static EncryptedData deserialize( byte[] data )
  {
    ByteBuffer buffer = ByteBuffer.wrap( data );

    int    saltLength = buffer.getInt();
    byte[] salt       = new byte[saltLength];
    buffer.get( salt );

    int    ivLength = buffer.getInt();
    byte[] iv       = new byte[ivLength];
    buffer.get( iv );

    int    tagLength = buffer.getInt();
    byte[] tag       = new byte[tagLength];
    buffer.get( tag );

    byte[] ciphertext = new byte[buffer.remaining()];
    buffer.get( ciphertext );

    return new EncryptedData( salt, iv, ciphertext, tag );
  }
}
