package core.service;

import io.vertx.core.Future;
import core.model.DilithiumKey;


public interface DilithiumKeyManagerIF
{
  /**
   * Initialize the key manager
   * @return Future completing when initialization is done
   */
  Future<Void> initialize();
  
  /**
   * Get the currently active signing key for this service
   * @return Active signing key, or null if none available
   */
  DilithiumKey getActiveSigningKey();
  
  /**
   * Get a verification key for the specified service and key ID
   * @param serviceId Service ID
   * @param keyId Key ID
   * @return Verification key, or null if not found
   */
  DilithiumKey getVerificationKey(String serviceId, String keyId);
  
  /**
   * Cache a verification key for future use
   * @param key Key to cache
   */
  void cacheVerificationKey(DilithiumKey key);
  
  /**
   * Check if the active signing key needs rotation
   * @return true if rotation is needed
   */
  boolean shouldRotateActiveKey();
  
  /**
   * Request a new signing key (implementation-specific)
   * @return Future with new signing key
   */
  Future<DilithiumKey> requestNewSigningKey();

}
