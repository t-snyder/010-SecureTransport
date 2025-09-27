package service;


import core.model.service.TopicKey;
import core.utils.KeyEpochUtil;

import java.security.SecureRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Instant;

/**
 * Stateless utility for generating epoch-based topic keys.
 */
public class TopicKeyGenerator
{
  private static final Logger LOGGER = LoggerFactory.getLogger( TopicKeyGenerator.class );
  private static final int AES_KEY_LENGTH = 32; // 256-bit

  private final SecureRandom secureRandom = new SecureRandom();

  public TopicKey createTopicKeyForEpoch( String topicName, long epochNumber )
  {
    Instant validFrom = KeyEpochUtil.epochStart(  epochNumber );
    Instant expiry    = KeyEpochUtil.epochExpiry( epochNumber );

    String keyId = String.format( "%s-epoch-%d", topicName, epochNumber );
    byte[] keyData = new byte[AES_KEY_LENGTH];
    secureRandom.nextBytes( keyData );

    LOGGER.debug( "Generated topic key for topic {}, epoch {}, valid {} to {}", topicName, epochNumber, validFrom, expiry );

    return new TopicKey( keyId, topicName, epochNumber, TopicKey.AES_ALGORITHM, keyData, validFrom, expiry, null );
  }
}