package core.service;


import core.model.DilithiumKey;
//import core.service.DilithiumService.DilithiumPrivateKey;
//import core.service.DilithiumService.DilithiumPublicKey;
import core.utils.KeyEpochUtil;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.security.KeyPair;
import java.time.Instant;
import java.security.SecureRandom;

/**
 * Utility for generating Dilithium signing keys per service and epoch.
 */
public class DilithiumKeyGenerator
{

  public DilithiumKey createSigningKeyForEpoch( String serviceId, long epochNumber )
  {
    // Generate Dilithium keypair using BouncyCastle
    DilithiumKeyPairGenerator generator = new DilithiumKeyPairGenerator();
    generator.init( new DilithiumKeyGenerationParameters( new SecureRandom(), DilithiumParameters.dilithium5 ) );
    AsymmetricCipherKeyPair kp = generator.generateKeyPair();

    DilithiumPublicKeyParameters  pub  = (DilithiumPublicKeyParameters)kp.getPublic();
    DilithiumPrivateKeyParameters priv = (DilithiumPrivateKeyParameters)kp.getPrivate();

    KeyPair keyPair = new KeyPair( new DilithiumService.DilithiumPublicKey( pub ), new DilithiumService.DilithiumPrivateKey( priv ) );

    Instant validFrom = KeyEpochUtil.epochStart(  epochNumber );
    Instant expiry    = KeyEpochUtil.epochExpiry( epochNumber );

    String keyId = String.format( "%d", epochNumber );

    // UsageLimit=0 means unlimited
    return new DilithiumKey( keyId, serviceId, keyPair, epochNumber, validFrom, expiry );
  }
}