package service;


import core.model.service.TopicKey;
import core.utils.KeyEpochUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stores all topic keys by topic and epoch, ensuring standard epochs.
 */
public class TopicKeyStore
{
  private static final Logger LOGGER = LoggerFactory.getLogger( TopicKeyStore.class );

  private final Map<String, Map<Long, TopicKey>> topicEpochKeys = new ConcurrentHashMap<>();
  private final TopicKeyGenerator keyGenerator;

  public TopicKeyStore( TopicKeyGenerator keyGenerator )
  {
    this.keyGenerator = keyGenerator;
  }

  /**
   * Gets all valid keys for the topic (previous, current, next epochs).
   */
  public synchronized Map<String, TopicKey> getAllValidKeysForTopic( String topicName )
  {
    Map<Long, TopicKey> byEpoch = topicEpochKeys.computeIfAbsent( topicName, k -> new HashMap<>() );
    Instant now = Instant.now();
    long nowEpoch = KeyEpochUtil.epochNumberForInstant( now );
    List<Long> neededEpochs = Arrays.asList( nowEpoch - 1, nowEpoch, nowEpoch + 1 );

    Map<String, TopicKey> result = new HashMap<>();
    for( long epoch : neededEpochs )
    {
      TopicKey key = byEpoch.get( epoch );
      if( key == null )
      {
        key = keyGenerator.createTopicKeyForEpoch( topicName, epoch );
        byEpoch.put( epoch, key );
        LOGGER.debug( "Generated topic key for topic {}, epoch {}", topicName, epoch );
      }
      if( !key.isExpired() )
      {
        result.put( key.getKeyId(), key );
      }
    }
    pruneExpiredEpochs( byEpoch );
    return result;
  }

  private void pruneExpiredEpochs( Map<Long, TopicKey> byEpoch )
  {
    byEpoch.entrySet().removeIf( e -> e.getValue().isExpired() );
  }
}