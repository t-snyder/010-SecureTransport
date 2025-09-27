package core.crypto;


import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.SecureRandom;
import java.util.Base64;

public class Argon2Hash
{
  private static final int NUM_THREADS = 1;
  private static final int MEMORY_SZ   = 65536; // 64MB
  private static final int ITERATIONS  = 3;
  
  public static String hash( String pwd )
  {
    byte[]       salt   = new byte[16];
    SecureRandom random = new SecureRandom();
    random.nextBytes( salt );

    // Argon2id is recommended
    Argon2Parameters.Builder builder = new Argon2Parameters.Builder( Argon2Parameters.ARGON2_id )
                                                           .withSalt( salt )
                                                           .withParallelism( NUM_THREADS ) // Number of threads
                                                           .withMemoryAsKB( MEMORY_SZ )    // 64 MB
                                                           .withIterations( ITERATIONS );  // Number of iterations

    Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init( builder.build() );

    byte[] hash = new byte[32]; // 256-bit hash
    generator.generateBytes( pwd.getBytes(), hash, 0, hash.length );

    return Base64.getEncoder().encodeToString( salt ) + ":" + Base64.getEncoder().encodeToString( hash );
  }
}