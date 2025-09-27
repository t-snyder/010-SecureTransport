package service;


import core.model.DilithiumKey;
import core.service.DilithiumKeyGenerator;
import core.utils.KeyEpochUtil;
import verticle.ServicesACLWatcherVert;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Stores all Dilithium signing keys by service and epoch.
 */
public class ServiceDilithiumKeyStore
{
  private static final Logger LOGGER = LoggerFactory.getLogger( ServiceDilithiumKeyStore.class );
  
  private final Map<String, Map<Long, DilithiumKey>> serviceEpochKeys = new ConcurrentHashMap<>();
  private final DilithiumKeyGenerator keyGenerator;

  public ServiceDilithiumKeyStore( DilithiumKeyGenerator keyGenerator )
  {
    this.keyGenerator = keyGenerator;
  }

  /**
   * Gets all valid (not expired) signing keys for the service ( previous,
   * current, next epochs).
   */
  public synchronized Map<Long, DilithiumKey> getAllValidKeysForService( String serviceId )
  {
    Map<Long, DilithiumKey> byEpoch = serviceEpochKeys.computeIfAbsent( serviceId, k -> new HashMap<>() );
 
    Instant    now          = Instant.now();
    long       nowEpoch     = KeyEpochUtil.epochNumberForInstant( now );
    List<Long> neededEpochs = Arrays.asList( nowEpoch - 1, nowEpoch, nowEpoch + 1 );

    Map<Long, DilithiumKey> result = new HashMap<>();
    for( long epoch : neededEpochs )
    {
      DilithiumKey key = byEpoch.get( epoch );
      if( key == null )
      {
        key = keyGenerator.createSigningKeyForEpoch( serviceId, epoch );
        byEpoch.put( epoch, key );
      }
      if( !key.isExpired() )
      {
        result.put( epoch, key );
      }
    }
    
    pruneExpiredEpochs( byEpoch );
    return result;
  }

  /**
   * Gets only the public part of all valid keys (for verification) for a
   * service.
   */
  public synchronized Map<Long, DilithiumKey> getAllValidVerifyKeysForService( String serviceId )
  {
    Map<Long, DilithiumKey> signingKeys = getAllValidKeysForService( serviceId );
    Map<Long, DilithiumKey> verifyKeys  = new HashMap<>();
 
    for( DilithiumKey key : signingKeys.values() )
    {
      // Only public part
      DilithiumKey pubKey = new DilithiumKey( key.getKeyId(), key.getServiceId(), key.getPublicKey(), key.getEpochNumber(), key.getCreateTime(), key.getExpiryTime() );
      verifyKeys.put( key.getEpochNumber(), pubKey );
    }
    
    return verifyKeys;
  }

  private void pruneExpiredEpochs( Map<Long, DilithiumKey> byEpoch )
  {
    byEpoch.entrySet().removeIf( e -> e.getValue().isExpired() );
  }
}