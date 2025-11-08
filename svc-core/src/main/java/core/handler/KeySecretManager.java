package core.handler;


import io.vertx.core.Future;
import io.vertx.core.Vertx;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.model.DilithiumKey;
import core.model.ServiceBundle;
import core.model.SharedSecretInfo;
import core.model.service.TopicKey;
import core.model.service.TopicPermission;
import core.utils.KeyEpochUtil;

/**
 * Complete unified key manager for all key types: - Shared secrets for
 * service-to-service communication - Dilithium signing keys for message
 * authentication - Topic encryption keys for message content encryption
 * 
 * Handles storage and retrieval only - no rotation logic
 */
public class KeySecretManager
{
  private static final Logger   LOGGER = LoggerFactory.getLogger(KeySecretManager.class.getName());
  private static final Duration KEY_CLEANUP_GRACE_PERIOD   = Duration.ofMinutes(60);
  private static final int      TOPIC_KEY_RETENTION_EPOCHS = 20;  // Keep 20 epochs (100 minutes)

  private final Vertx vertx;

  // Storage for different key types
  // Currently shared secrets are only stored for secrets with the deployed service and the metadata service.
  private final ConcurrentHashMap<String, ConcurrentHashMap<String, SharedSecretInfo>> sharedSecrets; // serviceId -> (keyId -> key)
  private final ConcurrentHashMap<String, ConcurrentHashMap<Long,   DilithiumKey>>     verifyKeys;    // serviceId -> {epoch -> key}
  private final ConcurrentHashMap<String, ConcurrentHashMap<String, TopicKey>>         topicKeys;     // topicName -> {keyId -> key}
  private final ConcurrentHashMap<String, TopicPermission> topicPermissions = new ConcurrentHashMap<>();

  // KeyId = epochNumber );
  private final ConcurrentHashMap<Long, DilithiumKey> signingKeys; // {keyId -> key}
  
  private final Map<String, Long>  cacheRefreshTimes; // When each service's keys were last refreshed
  private final VaultAccessHandler vaultHandler;

  private Map<String, KeyPair> kyberKeyPair = new HashMap<String, KeyPair>();; // In process key exchange

  // Track which epochs we've loaded from key exchange or directly from Vault 
  private final ConcurrentHashMap<Long, ServiceBundle> loadedServiceBundleEpochs = new ConcurrentHashMap<>();

  /**
   * Creates a new KeySecretManager with unified key storage
   * 
   * @param vertx
   *          Vert.x instance
   * @param vaultHandler
   *          Vault access handler for retrieving public keys
   */
  public KeySecretManager( Vertx vertx, VaultAccessHandler vaultHandler )
  {
    this.vertx        = vertx;
    this.vaultHandler = vaultHandler;
    
    this.sharedSecrets     = new ConcurrentHashMap<>();
    this.verifyKeys        = new ConcurrentHashMap<>();
    this.signingKeys       = new ConcurrentHashMap<>();
    this.topicKeys         = new ConcurrentHashMap<>();
    this.cacheRefreshTimes = new ConcurrentHashMap<>();

    // Set up periodic cleanup of expired keys (all types)
    this.vertx.setPeriodic( 300000, id -> cleanupExpiredKeys() );

    LOGGER.info( "KeySecretManager initialized with unified key storage" );
  }

  /**
   * Load all keys and permissions from a ServiceBundle into the KeySecretManager.
   * This includes: signingKeys, verifyKeys, topicKeys, and topicPermissions.
   * Also marks loaded epochs into loadedServiceBundleEpochs for the corresponding services.
   */
  public void loadFromServiceBundle( ServiceBundle bundle )
  {
    // Signing keys
    if( bundle.getSigningKeys() != null )
    {
      for( Map.Entry<Long, DilithiumKey> entry : bundle.getSigningKeys().entrySet() )
      {
        DilithiumKey dKey = entry.getValue();
        addSigningKeyToCache( dKey );
      }
      LOGGER.debug( "Loaded {} signing keys from ServiceBundle", bundle.getSigningKeys().size() );
    }

    // 2. Verify keys (for peer services)
    if( bundle.getVerifyKeys() != null )
    {
      for( Map.Entry<String, Map<Long, DilithiumKey>> svcEntry : bundle.getVerifyKeys().entrySet() )
      {
        String serviceId = svcEntry.getKey();
        Map<Long, DilithiumKey> svcKeys = svcEntry.getValue();
        if( svcKeys != null )
        {
          ConcurrentHashMap<Long, DilithiumKey> cache = this.verifyKeys.computeIfAbsent( serviceId, k -> new ConcurrentHashMap<>() );
          for( Map.Entry<Long, DilithiumKey> keyEntry : svcKeys.entrySet() )
          {
            cache.put( keyEntry.getKey(), keyEntry.getValue() );
          }
          LOGGER.debug( "Loaded {} verify keys for service {} from ServiceBundle", svcKeys.size(), serviceId );
        }
      }
    }

    // Topic keys
    if( bundle.getTopicKeys() != null )
    {
      for( Map.Entry<String, Map<String, TopicKey>> topicEntry : bundle.getTopicKeys().entrySet() )
      {
        String topic = topicEntry.getKey();
        Map<String, TopicKey> keyMap = topicEntry.getValue();
        if( keyMap != null )
        {
          for( TopicKey topicKey : keyMap.values() )
          {
            this.storeTopicKey( topicKey );
          }
          LOGGER.debug( "Loaded {} topic keys for topic {} from ServiceBundle", keyMap.size(), topic );
        }
      }
    }

    // 4. Topic permissions (track in new field)
    if( bundle.getTopicPermissions() != null )
    {
      for( Map.Entry<String, TopicPermission> entry : bundle.getTopicPermissions().entrySet() )
      {
        this.topicPermissions.put( entry.getKey(), entry.getValue() );
      }
      LOGGER.debug( "Loaded {} topic permissions from ServiceBundle", bundle.getTopicPermissions().size() );
    }
    
    // mark the explicit (service, epoch) we requested
    loadedServiceBundleEpochs.put( bundle.getKeyEpoch(), bundle );
  }
 
  /**
   *Check if we have a specific epoch loaded for a service
   */
  public boolean hasServiceBundleForEpoch( long epoch ) 
  {
    return loadedServiceBundleEpochs.contains(epoch);
  }
  
  /**
   * Load a specific ServiceBundle epoch from Vault on-demand
   */
  public Future<Void> loadServiceBundleForEpoch(String targetServiceId, long epoch)
  {
    // Check if already loaded
    if (hasServiceBundleForEpoch( epoch ))
    {
      LOGGER.debug("ServiceBundle for epoch {} already loaded", epoch );
      return Future.succeededFuture();
    }

    LOGGER.info("Fetching ServiceBundle from Vault: service='{}', epoch={}", targetServiceId, epoch);

    return vaultHandler.getServiceBundle( targetServiceId, epoch )
      .compose( bundle -> 
       {  // Use compose instead of onSuccess
         loadFromServiceBundle(bundle);

         LOGGER.info("✅ Loaded ServiceBundle from Vault: service='{}', epoch={}", targetServiceId, epoch);
         return Future.<Void>succeededFuture();
       })
      .recover( err -> 
       {
         LOGGER.error("Failed to load ServiceBundle from Vault: service='{}', epoch={}, error={}",
                      targetServiceId, epoch, err.getMessage(), err);
         return Future.failedFuture(err);
       });
  }  
  
  // ========================================================================
  // SHARED SECRET MANAGEMENT (EXISTING - COMPLETE)
  // ========================================================================

  /**
   * Temp store for inprocess keypair for key exchange
   */
  public void putKyberKeyPair( String keyId, KeyPair keyPair )
  {
    if( keyId == null || keyId.isBlank() )
      return;
    if( keyPair == null )
      return;
    
    kyberKeyPair.put( keyId, keyPair );
  }
 
  public PublicKey getKyberPublicKey( String keyId )
  {
    if( kyberKeyPair.containsKey( keyId ))
    {
      KeyPair keyPair = kyberKeyPair.get( keyId );
      return keyPair.getPublic();
    }
    
    return null;
  }

  public PrivateKey getKyberPrivateKey( String keyId )
  {
    if( kyberKeyPair.containsKey( keyId ))
    {
      KeyPair keyPair = kyberKeyPair.get( keyId );
      return keyPair.getPrivate();
    }
    
    return null;
  }
  
  /**
   * Stores an encryption shared secret in memory for the given service ID These
   * secrets are NOT persisted to disk.
   * 
   * @param keyInfo
   *          the shared secret information
   */
  public void putEncyptionSharedSecret( SharedSecretInfo keyInfo )
  {
    try
    {
      validateSharedSecret( keyInfo );

      ConcurrentHashMap<String, SharedSecretInfo> serviceMap = sharedSecrets.get( keyInfo.getSourceSvcId() );

      if( serviceMap == null )
      {
        serviceMap = new ConcurrentHashMap<>();
        sharedSecrets.put( keyInfo.getSourceSvcId(), serviceMap );
      }

      serviceMap.put( keyInfo.getKeyId(), keyInfo );
      cleanupExpiredSharedSecrets( keyInfo.getSourceSvcId() );

      LOGGER.debug( "SharedSecretInfo stored in memory for service: {}", keyInfo.getSourceSvcId() );
    } 
    catch( Exception e )
    {
      LOGGER.error( "Error storing SharedSecretInfo. Error = " + e.getMessage() );
    }
  }

  /**
   * Retrieves a shared secret for the given service ID and key ID
   * 
   * @param serviceId
   *          the unique identifier for the service
   * @param keyId
   *          the key identifier
   * @return the shared secret info or null if not found
   * @throws Exception
   *           if the parameters are invalid
   */
  public SharedSecretInfo getSharedSecretInfo( String serviceId, String keyId ) throws Exception
  {
    if( ( serviceId == null || serviceId.isBlank() ) || ( keyId == null || keyId.isBlank() ) )
    {
      String errMsg = "KeySecretManager.getSharedSecretInfo found invalid serviceId, or keyId";
      LOGGER.error( errMsg );
      throw new Exception( errMsg );
    }

    ConcurrentHashMap<String, SharedSecretInfo> serviceMap = sharedSecrets.get( serviceId );
    if( serviceMap == null )
    {
      LOGGER.info( "Shared secret map not found for serviceId = " + serviceId );
      return null;
    }

    return serviceMap.get( keyId );
  }

  /**
   * Retrieves all shared secrets for the given service ID
   * 
   * @param serviceId
   *          the unique identifier for the service
   * @return collection of shared secrets or null if service not found
   * @throws Exception
   *           if the serviceId is invalid
   */
  public Collection<SharedSecretInfo> getServiceSharedSecrets( String serviceId ) throws Exception
  {
    if( serviceId == null || serviceId.isBlank() )
    {
      String errMsg = "KeySecretManager.getServiceSharedSecrets found invalid serviceId";
      LOGGER.error( errMsg );
      throw new Exception( errMsg );
    }

    ConcurrentHashMap<String, SharedSecretInfo> serviceMap = sharedSecrets.get( serviceId );
    if( serviceMap == null )
    {
      LOGGER.info( "Shared secret map not found for serviceId = " + serviceId );
      return null;
    }

    return serviceMap.values();
  }

  /**
   * Get shared secrets sorted by expiry time
   */
  public List<SharedSecretInfo> getServiceSharedSecretKeysSorted( String serviceId ) throws Exception
  {
    Collection<SharedSecretInfo> keys = getServiceSharedSecrets( serviceId );
    if( keys == null || keys.isEmpty() )
      return null;

    List<SharedSecretInfo> sortedKeys = keys.stream().sorted( Comparator.comparing( SharedSecretInfo::getExpires ) ).collect( Collectors.toList() );

    return sortedKeys;
  }

  /**
   * Get the most recent shared secret (latest expiry)
   */
  public SharedSecretInfo getMostRecentSharedSecret( String serviceId ) throws Exception
  {
    Collection<SharedSecretInfo> keys = getServiceSharedSecrets( serviceId );
    if( keys == null || keys.isEmpty() )
      return null;

    SharedSecretInfo mostRecentKey = keys.stream().max( Comparator.comparing( SharedSecretInfo::getExpires ) ).orElse( null );

    return mostRecentKey;
  }

  /**
   * Cleanup expired shared secrets for a service
   */
  public void cleanupExpiredSharedSecrets( String serviceId )
  {
    Instant now = Instant.now();
    Instant cutoff = now.minus( KEY_CLEANUP_GRACE_PERIOD );

    ConcurrentHashMap<String, SharedSecretInfo> serviceMap = sharedSecrets.get( serviceId );
    if( serviceMap == null )
    {
      LOGGER.info( "Nothing to cleanup for serviceId = " + serviceId );
      return;
    }

    Iterator<Map.Entry<String, SharedSecretInfo>> iter = serviceMap.entrySet().iterator();
    while( iter.hasNext() )
    {
      Map.Entry<String, SharedSecretInfo> entry = iter.next();
      Instant keyExpiry = entry.getValue().getExpires();
      if( keyExpiry.isBefore( cutoff ) )
      {
        iter.remove();
        LOGGER.info( "Removing expired SharedSecret for target {} with expiry {} (grace period: {})", serviceId, keyExpiry, KEY_CLEANUP_GRACE_PERIOD );
      }
    }
  }

  /**
   * Removes a shared secret for the given service ID and key ID
   * 
   * @param serviceId
   *          the unique identifier for the service
   * @param keyId
   *          the key identifier
   * @return true if the secret was removed, false if not found
   */
  public boolean removeSharedSecret( String serviceId, String keyId ) throws Exception
  {
    if( ( serviceId == null || serviceId.isBlank() ) || ( keyId == null || keyId.isBlank() ) )
    {
      String errMsg = "KeySecretManager.removeSharedSecret found invalid serviceId, or keyId";
      LOGGER.error( errMsg );
      throw new Exception( errMsg );
    }

    ConcurrentHashMap<String, SharedSecretInfo> serviceMap = sharedSecrets.get( serviceId );
    if( serviceMap == null )
    {
      LOGGER.info( "Shared secret map not found for serviceId = " + serviceId );
      return true; // Does not exist
    }

    if( serviceMap.containsKey( keyId ) )
    {
      serviceMap.remove( keyId );
      return true;
    }

    return true;
  }

  /**
   * Lists all service IDs that have stored shared secrets
   */
  public Set<String> listSharedSecretServiceIds()
  {
    return sharedSecrets.keySet();
  }

  // ========================================================================
  // DILITHIUM KEY MANAGEMENT (EXISTING - COMPLETE)
  // ========================================================================

  /**
   * Get a Dilithium public key, fetching from Vault if necessary
   * 
   * @param serviceId
   *          Service ID
   * @param keyId
   *          Key ID
   * @return Future with the key, or null if not found
   */
  public Future<DilithiumKey> getDilithiumPublicKey( String serviceId, long epoch )
  {
    if( ( serviceId == null || serviceId.isBlank() ) || ( epoch <= 0 ))
    {
      return Future.failedFuture( new IllegalArgumentException( "ServiceID and/or Epoch number cannot be null or empty" ) );
    }

    // Check if we have this key in cache
    Map<Long, DilithiumKey> serviceSigningKeys = verifyKeys.get( serviceId );
    if( serviceSigningKeys != null )
    {
      DilithiumKey key = serviceSigningKeys.get( epoch );
      if( key != null )
      {
        /** Check if expired
        if( key.isExpired() )
        {
          // Remove expired key
          serviceSigningKeys.remove( epoch );

          LOGGER.info( "Removed expired Dilithium public key: {}/{}", serviceId, epoch );
          return Future.failedFuture( new IllegalArgumentException( "ServiceID / Key ID not found." ));
        }
        */
        
        LOGGER.debug( "Found key {}:{} in local cache", serviceId, epoch );
        return Future.succeededFuture( key );
      }
    }
    
    return Future.failedFuture( new IllegalArgumentException( "ServiceID / Key ID not found." ));
  }

  /**
   * Add a key to the local cache (useful for testing or when keys are received
   * through other channels)
   * 
   * @param key
   *          The key to add to cache
   */
  public void addSigningKeyToCache( DilithiumKey key )
  {
    if( key == null )
    {
      throw new IllegalArgumentException( "Key cannot be null" );
    }

    signingKeys.put( key.getEpochNumber(), key );

    LOGGER.debug( "Added key {}:{} to local cache", key.getServiceId(), key.getKeyId() );
  }

  /**
   * Get the active signing key for this service
   */
  public DilithiumKey getSigningKey( long epoch )
  {
    return signingKeys.get( epoch );
  }

  // ========================================================================
  // TOPIC ENCRYPTION KEY MANAGEMENT (NEW)
  // ========================================================================

  /**
   * Store a topic encryption key
   * 
   * @param key
   *          The topic encryption key to store
   */
  /**
   * Store a topic encryption key
   */
  public void storeTopicKey( TopicKey key )
  {
    if( key == null )
    {
      throw new IllegalArgumentException( "Topic key cannot be null" );
    }

    String topicName = key.getTopicName();
    String keyId     = key.getKeyId();

    ConcurrentHashMap<String, TopicKey> topicKeyMap = topicKeys.computeIfAbsent( topicName, k -> new ConcurrentHashMap<>() );

    topicKeyMap.put( keyId, key );

    // Cleanup old keys for this topic using epoch retention
    cleanupExpiredTopicKeys( topicName );

    LOGGER.debug( "Stored topic encryption key: {} for topic: {} (expires: {})", keyId, topicName, key.getExpiryTime() );
  }
  
  /**
   * Get a specific topic encryption key by keyId
   */
  public TopicKey getTopicKey( String topicName, String keyId )
  {
    if( topicName == null || keyId == null )
    {
      return null;
    }

    ConcurrentHashMap<String, TopicKey> topicKeyMap = topicKeys.get( topicName );
    if( topicKeyMap == null )
    {
      return null;
    }

    // Return the key directly. Do not remove it here based on expiry timestamp;
    // cleanup is now governed by epoch retention policy.
    return topicKeyMap.get( keyId );
  }

  /**
   * Get all topic encryption keys for a topic (valid and expired)
   */
  public Collection<TopicKey> getAllTopicKeys( String topicName )
  {
    if( topicName == null )
    {
      return Collections.emptyList();
    }

    ConcurrentHashMap<String, TopicKey> topicKeyMap = topicKeys.get( topicName );
    if( topicKeyMap == null )
    {
      return Collections.emptyList();
    }

    return new ArrayList<>( topicKeyMap.values() );
  }

  /**
   * Get only valid (non-expired) topic encryption keys for a topic
   */
  public Collection<TopicKey> getValidTopicKeys( String topicName )
  {
    return getAllTopicKeys( topicName ).stream()
                                       .filter( key -> !key.isExpired() )
                                       .collect( Collectors.toList() );
  }

  /**
   * Get valid topic keys sorted by creation time (newest first)
   */
  public List<TopicKey> getValidTopicKeysSorted( String topicName )
  {
    return getValidTopicKeys( topicName ).stream().sorted( Comparator.comparing( TopicKey::getCreatedTime ).reversed() ).collect( Collectors.toList() );
  }

  /**
   * Get the newest valid key by creation time (for external rotation logic)
   */
  public TopicKey getNewestValidTopicKey( String topicName )
  {
    return getValidTopicKeys( topicName ).stream().max( Comparator.comparing( TopicKey::getCreatedTime ) ).orElse( null );
  }

  /**
   * Get the oldest valid key by creation time (for external rotation logic)
   */
  public TopicKey getOldestValidTopicKey( String topicName )
  {
    return getValidTopicKeys( topicName ).stream().min( Comparator.comparing( TopicKey::getCreatedTime ) ).orElse( null );
  }

  /**
   * Count valid keys for a topic (for external monitoring)
   */
  public int getValidTopicKeyCount( String topicName )
  {
    return getValidTopicKeys( topicName ).size();
  }

  /**
   * Check if topic has any valid keys (for external rotation logic)
   */
  public boolean hasValidTopicKey( String topicName )
  {
    return getValidTopicKeyCount( topicName ) > 0;
  }

  /**
   * Check if topic has multiple valid keys (for external transition monitoring)
   */
  public boolean hasMultipleValidTopicKeys( String topicName )
  {
    return getValidTopicKeyCount( topicName ) > 1;
  }

  /**
   * Remove a specific topic encryption key
  public boolean removeTopicKey( String topicName, String keyId )
  {
    if( topicName == null || keyId == null )
    {
      return false;
    }

    ConcurrentHashMap<String, TopicKey> topicKeyMap = topicKeys.get( topicName );
    if( topicKeyMap == null )
    {
      return false;
    }

    TopicKey removedKey = topicKeyMap.remove( keyId );
    if( removedKey != null )
    {
      // Clear sensitive data
      removedKey.clearKeyData();
      LOGGER.info( "Removed topic encryption key: {} for topic: {}", keyId, topicName );
      return true;
    }

    return false;
  }
   */

  /**
   * Remove all keys for a topic
  public int removeAllTopicKeys( String topicName )
  {
    if( topicName == null )
    {
      return 0;
    }

    ConcurrentHashMap<String, TopicKey> topicKeyMap = topicKeys.remove( topicName );
    if( topicKeyMap == null )
    {
      return 0;
    }

    int count = topicKeyMap.size();

    // Clear sensitive data from all keys
    topicKeyMap.values().forEach( TopicKey::clearKeyData );

    LOGGER.info( "Removed {} topic encryption keys for topic: {}", count, topicName );
    return count;
  }
   */

  /**
   * Get all topics that have stored keys
   */
  public Set<String> getAllTopicsWithKeys()
  {
    return Collections.unmodifiableSet( topicKeys.keySet() );
  }

  /**
   * Cleanup expired topic keys for a specific topic
   * Uses epoch retention: keep only keys with epoch >= newestEpoch - TOPIC_KEY_RETENTION_EPOCHS.
   * Keys with epoch < cutoffEpoch will be removed. Also removes cleaned epochs from loadedServiceBundleEpochs.
   */
  private void cleanupExpiredTopicKeys( String topicName )
  {
    long currentEpoch = KeyEpochUtil.epochNumberForInstant( Instant.now() );
    long cutoffEpoch  = currentEpoch - TOPIC_KEY_RETENTION_EPOCHS;

    ConcurrentHashMap<String, TopicKey> topicKeyMap = topicKeys.get( topicName );
    if( topicKeyMap == null || topicKeyMap.isEmpty() )
    {
      return;
    }

    Iterator<Map.Entry<String, TopicKey>> iter = topicKeyMap.entrySet().iterator();

    while( iter.hasNext() )
    {
      Map.Entry<String, TopicKey> entry = iter.next();
      TopicKey key = entry.getValue();

      if( key.getEpochNumber() < cutoffEpoch )
      {
        key.clearKeyData(); // Clear sensitive data
        iter.remove();
 
        LOGGER.debug( "Removed old topic key: {} for topic: {} (epoch: {}, cutoff: {})", key.getKeyId(), topicName, key.getEpochNumber(), cutoffEpoch );
      }
    }

    // Remove empty topic map
    if( topicKeyMap.isEmpty() )
    {
      topicKeys.remove( topicName );
    }
  }
  
  // ========================================================================
  // UNIFIED CLEANUP AND MANAGEMENT
  // ========================================================================

  /**
   * Enhanced cleanup that handles all key types
   */
  private void cleanupExpiredKeys()
  {
    LOGGER.debug( "Running comprehensive expired key cleanup" );

    // Cleanup shared secrets
    cleanupExpiredSharedSecretsAll();

    // Cleanup Dilithium verify keys
    cleanupExpiredDilithiumKeys();

    // Cleanup topic encryption keys
    cleanupAllExpiredTopicKeys();
    
    long currentEpoch = KeyEpochUtil.epochNumberForInstant( Instant.now() );
    long cutoffEpoch  = currentEpoch - TOPIC_KEY_RETENTION_EPOCHS;
 
    loadedServiceBundleEpochs.forEach((key, value) -> 
    {
      if( key < cutoffEpoch )
      {
        loadedServiceBundleEpochs.remove( key );
      }
    });
  }

  /**
   * Cleanup expired topic keys for all topics
   * Delegates to per-topic cleanup (epoch-retention based).
   */
  private void cleanupAllExpiredTopicKeys()
  {
    for( String topicName : new ArrayList<>( topicKeys.keySet() ) )
    {
      cleanupExpiredTopicKeys( topicName );
    }
  }

  /**
   * Cleanup expired shared secrets for all services
   */
  private void cleanupExpiredSharedSecretsAll()
  {
    for( String serviceId : new ArrayList<>( sharedSecrets.keySet() ) )
    {
      cleanupExpiredSharedSecrets( serviceId );
    }
  }

  /**
   * Cleanup expired Dilithium verify keys
   * Now uses retention by epoch: for each service, determine newest epoch and
   * remove keys with epoch < (newestEpoch - TOPIC_KEY_RETENTION_EPOCHS).
   * Also ensures loadedServiceBundleEpochs is unmarked for removed epochs.
   */
  private void cleanupExpiredDilithiumKeys()
  {
    long currentEpoch = KeyEpochUtil.epochNumberForInstant( Instant.now() );
    long cutoffEpoch  = currentEpoch - TOPIC_KEY_RETENTION_EPOCHS;
    
    for( Map.Entry<String, ConcurrentHashMap<Long, DilithiumKey>> serviceEntry : verifyKeys.entrySet() )
    {
      String serviceId = serviceEntry.getKey();
      Map<Long, DilithiumKey> serviceKeys = serviceEntry.getValue();
      if( serviceKeys == null || serviceKeys.isEmpty() )
        continue;

      List<Long> toRemove = serviceKeys.keySet().stream()
                                       .filter(epoch -> epoch < cutoffEpoch)
                                       .collect( Collectors.toList() );

      if( !toRemove.isEmpty() )
      {
        for( Long epoch : toRemove )
        {
          serviceKeys.remove( epoch );
        }

        LOGGER.info( "Removed {} old Dilithium keys for service {} (kept last {} epochs, newestEpoch={})", toRemove.size(), serviceEntry.getKey(), TOPIC_KEY_RETENTION_EPOCHS, currentEpoch );
      }
    }
  }

  /**
   * Clear all stored keys (all types)
   */
  public void clearAll()
  {
    // Clear sensitive data before removing references
    topicKeys.values().forEach( topicMap -> topicMap.values().forEach( TopicKey::clearKeyData ) );

    sharedSecrets.clear();
    verifyKeys.clear();
    signingKeys.clear();
    topicKeys.clear();
    cacheRefreshTimes.clear();
    loadedServiceBundleEpochs.clear();

    LOGGER.info( "Cleared all secrets and cached keys (including topic encryption keys)" );
  }

  // ========================================================================
  // VALIDATION HELPERS
  // ========================================================================

  private void validateSharedSecret( SharedSecretInfo keyInfo )
  {
    if( keyInfo.getKeyId() == null || keyInfo.getKeyId().trim().isEmpty() )
    {
      throw new IllegalArgumentException( "Key ID cannot be null or empty" );
    }

    if( keyInfo.getSourceSvcId() == null || keyInfo.getSourceSvcId().trim().isEmpty() )
    {
      throw new IllegalArgumentException( "Source Service ID cannot be null or empty" );
    }

    if( keyInfo.getTargetSvcId() == null || keyInfo.getTargetSvcId().trim().isEmpty() )
    {
      throw new IllegalArgumentException( "Target Service ID cannot be null or empty" );
    }

    if( keyInfo.getPublicKey() == null || keyInfo.getPublicKey().length < 1 )
    {
      throw new IllegalArgumentException( "Public key cannot be null or empty" );
    }

    if( keyInfo.getSharedSecret() == null || keyInfo.getSharedSecret().length < 1 )
    {
      throw new IllegalArgumentException( "Shared secret cannot be null or empty" );
    }

    if( keyInfo.getCreated() == null )
    {
      throw new IllegalArgumentException( "Created time cannot be null" );
    }

    if( keyInfo.getExpires() == null )
    {
      throw new IllegalArgumentException( "Expires time cannot be null" );
    }
  }

  // ------------------------------------------------------------------------
  // Helpers to maintain loadedServiceBundleEpochs in a concurrency-safe manner
  // ------------------------------------------------------------------------

  /**
   * Mark that we've loaded a service bundle epoch for a given service.
  private void markLoadedEpoch(String serviceId, long epoch)
  {
    if (serviceId == null || serviceId.isBlank() || epoch <= 0)
      return;

    Set<Long> set = loadedServiceBundleEpochs.computeIfAbsent(serviceId, k -> ConcurrentHashMap.newKeySet());
    set.add(epoch);
  }
   */

  /**
   * Unmark (remove) an epoch for a specific service. If the set becomes empty
   * the service entry is removed.
  private void unmarkLoadedEpoch(String serviceId, long epoch)
  {
    if (serviceId == null || epoch <= 0)
      return;

    Set<Long> set = loadedServiceBundleEpochs.get(serviceId);
    if (set != null)
    {
      set.remove(epoch);
      if (set.isEmpty())
      {
        // conditional remove to avoid race
        loadedServiceBundleEpochs.remove(serviceId, set);
      }
    }
  }
   */

  /**
   * Unmark (remove) an epoch from all services' sets. This is used when keys
   * for a given epoch are cleaned by topic cleanup and we want loadedServiceBundleEpochs
   * to reflect that.
  private void unmarkLoadedEpochGlobally(long epoch)
  {
    if (epoch <= 0)
      return;

    // iterate over a snapshot to avoid concurrent modification surprises
    for (Map.Entry<String, Set<Long>> entry : new ArrayList<>(loadedServiceBundleEpochs.entrySet()))
    {
      String svc = entry.getKey();
      Set<Long> set = entry.getValue();
      if (set != null && set.remove(epoch))
      {
        if (set.isEmpty())
        {
          loadedServiceBundleEpochs.remove(svc, set);
        }
      }
    }
  }
   */
  
}