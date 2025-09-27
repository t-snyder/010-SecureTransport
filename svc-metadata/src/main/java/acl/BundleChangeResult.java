package acl;

import java.util.*;

import core.model.ServiceBundle;

/**
 * Tracks changes in service bundles during ACL configuration updates
 * Distinguishes between permission changes and key rotation changes
 */
public class BundleChangeResult
{
  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(BundleChangeResult.class);
  
  // Permission-based changes
  private final Map<String, ServiceBundle> permissionChangedBundles = new HashMap<>();
  private final Map<String, ServiceBundle> newBundles = new HashMap<>(); 
  private final Map<String, ServiceBundle> removedBundles = new HashMap<>();
  private final Map<String, ServiceBundle> unchangedBundles = new HashMap<>();
  
  // Key rotation changes
  private final Map<String, ServiceBundle> keyRotationBundles = new HashMap<>();
  private final Map<String, Set<String>>   rotatedTopicsByService = new HashMap<>();
  
  // Combined tracking
  private final Map<String, ChangeType> serviceChangeTypes = new HashMap<>();
  
  /**
   * Add a bundle that has permission changes (topics added/removed, access modified)
   */
  public void addPermissionChangedBundle(String serviceId, ServiceBundle bundle)
  {
    permissionChangedBundles.put(serviceId, bundle);
    updateChangeType(serviceId, ChangeType.PERMISSION_CHANGED);
    LOGGER.debug("Marked service bundle as permission changed: {}", serviceId);
  }
  
  /**
   * Add a bundle that has key rotation changes (encryption keys rotated)
   */
  public void addKeyRotationBundle(String serviceId, ServiceBundle bundle, Set<String> rotatedTopics)
  {
    keyRotationBundles.put(serviceId, bundle);
    rotatedTopicsByService.put(serviceId, new HashSet<>(rotatedTopics));
    updateChangeType(serviceId, ChangeType.KEY_ROTATION);
    LOGGER.debug("Marked service bundle as key rotation: {} (topics: {})", serviceId, rotatedTopics);
  }
  
  /**
   * Add a bundle that has both permission and key rotation changes
   */
  public void addCombinedChangeBundle(String serviceId, ServiceBundle bundle, Set<String> rotatedTopics)
  {
    permissionChangedBundles.put(serviceId, bundle);
    keyRotationBundles.put(serviceId, bundle);
    rotatedTopicsByService.put(serviceId, new HashSet<>(rotatedTopics));
    updateChangeType(serviceId, ChangeType.COMBINED_CHANGE);
    LOGGER.debug("Marked service bundle as combined change: {} (topics: {})", serviceId, rotatedTopics);
  }
  
  /**
   * Add a completely new service bundle
   */
  public void addNewBundle(String serviceId, ServiceBundle bundle)
  {
    newBundles.put(serviceId, bundle);
    updateChangeType(serviceId, ChangeType.NEW);
    LOGGER.debug("Marked service bundle as new: {}", serviceId);
  }
  
  /**
   * Add a bundle that was removed (service no longer has permissions)
   */
  public void addRemovedBundle(String serviceId, ServiceBundle bundle)
  {
    removedBundles.put(serviceId, bundle);
    updateChangeType(serviceId, ChangeType.REMOVED);
    LOGGER.debug("Marked service bundle as removed: {}", serviceId);
  }
  
  /**
   * Add a bundle that has not changed
   */
  public void addUnchangedBundle(String serviceId, ServiceBundle bundle)
  {
    unchangedBundles.put(serviceId, bundle);
    updateChangeType(serviceId, ChangeType.UNCHANGED);
    LOGGER.debug("Marked service bundle as unchanged: {}", serviceId);
  }
  
  /**
   * Update the change type for a service, handling combinations
   */
  private void updateChangeType(String serviceId, ChangeType newType)
  {
    ChangeType existing = serviceChangeTypes.get(serviceId);
    
    if (existing == null)
    {
      serviceChangeTypes.put(serviceId, newType);
    }
    else if (existing == ChangeType.PERMISSION_CHANGED && newType == ChangeType.KEY_ROTATION)
    {
      serviceChangeTypes.put(serviceId, ChangeType.COMBINED_CHANGE);
    }
    else if (existing == ChangeType.KEY_ROTATION && newType == ChangeType.PERMISSION_CHANGED)
    {
      serviceChangeTypes.put(serviceId, ChangeType.COMBINED_CHANGE);
    }
    else
    {
      serviceChangeTypes.put(serviceId, newType);
    }
  }
  
  // Getters for different change types
  public Map<String, ServiceBundle> getPermissionChangedBundles() { return new HashMap<>(permissionChangedBundles); }
  public Map<String, ServiceBundle> getKeyRotationBundles()       { return new HashMap<>(keyRotationBundles); }
  public Map<String, ServiceBundle> getNewBundles()               { return new HashMap<>(newBundles); }
  public Map<String, ServiceBundle> getRemovedBundles()           { return new HashMap<>(removedBundles); }
  public Map<String, ServiceBundle> getUnchangedBundles()         { return new HashMap<>(unchangedBundles); }
  
  // Service sets
  public Set<ServiceBundle> getPermissionChangedServices() { return new HashSet<>( permissionChangedBundles.values() ); }
  public Set<String> getKeyRotationServices()       { return new HashSet<>( keyRotationBundles.keySet()); }
  public Set<String> getNewServices()               { return new HashSet<>( newBundles.keySet()); }
  public Set<String> getRemovedServices()           { return new HashSet<>( removedBundles.keySet()); }
  public Set<String> getUnchangedServices()         { return new HashSet<>( unchangedBundles.keySet()); }
  
  /**
   * Get all services that experienced changes (excludes unchanged)
   */
  public Set<String> getChangedServices()
  {
    Set<String> changed = new HashSet<>();
    changed.addAll(permissionChangedBundles.keySet());
    changed.addAll(keyRotationBundles.keySet());
    changed.addAll(newBundles.keySet());
    changed.addAll(removedBundles.keySet());
    return changed;
  }
  
  /**
   * Get services that need bundle redistribution (all changes except unchanged)
   */
  public Set<String> getServicesNeedingRedistribution()
  {
    Set<String> needsRedistribution = new HashSet<>();
    needsRedistribution.addAll(permissionChangedBundles.keySet());
    needsRedistribution.addAll(keyRotationBundles.keySet());
    needsRedistribution.addAll(newBundles.keySet());
    return needsRedistribution;
  }
  
  /**
   * Get services that need immediate key exchange (permission changes and new services)
   */
  public Set<String> getServicesNeedingKeyExchange()
  {
    Set<String> needsKeyExchange = new HashSet<>();
    needsKeyExchange.addAll(permissionChangedBundles.keySet());
    needsKeyExchange.addAll(newBundles.keySet());
    return needsKeyExchange;
  }
  
  /**
   * Get services that need update processing (all types of changes)
   */
  public Set<String> getServicesNeedingUpdate()
  {
    return getChangedServices();
  }
  
  /**
   * Get rotated topics for a service
   */
  public Set<String> getRotatedTopicsForService(String serviceId)
  {
    return rotatedTopicsByService.getOrDefault(serviceId, Collections.emptySet());
  }
  
  /**
   * Check what type of change a service has
   */
  public ChangeType getChangeType(String serviceId)
  {
    return serviceChangeTypes.getOrDefault(serviceId, ChangeType.UNKNOWN);
  }
  
  /**
   * Get bundle for a service regardless of change type
   */
  public ServiceBundle getBundleForService(String serviceId)
  {
    if( permissionChangedBundles.containsKey(serviceId))
    {
      return permissionChangedBundles.get( serviceId );
    }
    else if (keyRotationBundles.containsKey(serviceId))
    {
      return keyRotationBundles.get(serviceId);
    }
    else if (newBundles.containsKey(serviceId))
    {
      return newBundles.get(serviceId);
    }
    else if (unchangedBundles.containsKey(serviceId))
    {
      return unchangedBundles.get(serviceId);
    }
    else if (removedBundles.containsKey(serviceId))
    {
      return removedBundles.get(serviceId);
    }
    return null;
  }
  
  /**
   * Check if there are any changes requiring processing
   */
  public boolean hasChanges()
  {
    return !permissionChangedBundles.isEmpty() || 
           !keyRotationBundles.isEmpty() || 
           !newBundles.isEmpty() || 
           !removedBundles.isEmpty();
  }
  
  /**
   * Check if there are permission-related changes (trigger key exchange)
   */
  public boolean hasPermissionChanges()
  {
    return !permissionChangedBundles.isEmpty() || !newBundles.isEmpty() || !removedBundles.isEmpty();
  }
  
  /**
   * Check if there are key rotation changes (bundle update only)
   */
  public boolean hasKeyRotationChanges()
  {
    return !keyRotationBundles.isEmpty();
  }
  
  /**
   * Merge another BundleChangeResult into this one
   */
  public void merge(BundleChangeResult other)
  {
    // Merge permission changes
    for (Map.Entry<String, ServiceBundle> entry : other.permissionChangedBundles.entrySet())
    {
      addPermissionChangedBundle(entry.getKey(), entry.getValue());
    }
    
    // Merge key rotations
    for (Map.Entry<String, ServiceBundle> entry : other.keyRotationBundles.entrySet())
    {
      String serviceId = entry.getKey();
      Set<String> rotatedTopics = other.getRotatedTopicsForService(serviceId);
      addKeyRotationBundle(serviceId, entry.getValue(), rotatedTopics);
    }
    
    // Merge other categories
    newBundles.putAll(other.newBundles);
    removedBundles.putAll(other.removedBundles);
    unchangedBundles.putAll(other.unchangedBundles);
    
    // Update change types
    for (Map.Entry<String, ChangeType> entry : other.serviceChangeTypes.entrySet())
    {
      updateChangeType(entry.getKey(), entry.getValue());
    }
  }
  
  /**
   * Generate summary for logging and monitoring
   */
  public io.vertx.core.json.JsonObject generateSummary()
  {
    io.vertx.core.json.JsonObject summary = new io.vertx.core.json.JsonObject();
    
    summary.put("permissionChanged", permissionChangedBundles.size());
    summary.put("keyRotation", keyRotationBundles.size());
    summary.put("newServices", newBundles.size());
    summary.put("removedServices", removedBundles.size());
    summary.put("unchangedServices", unchangedBundles.size());
    summary.put("totalServices", getTotalServiceCount());
    
    summary.put("hasPermissionChanges", hasPermissionChanges());
    summary.put("hasKeyRotationChanges", hasKeyRotationChanges());
    summary.put("needsRedistribution", getServicesNeedingRedistribution().size());
    summary.put("needsKeyExchange", getServicesNeedingKeyExchange().size());
    
    summary.put("timestamp", System.currentTimeMillis());
    
    // Add service lists for detailed tracking
    summary.put("changedServices", new io.vertx.core.json.JsonArray(new ArrayList<>(getChangedServices())));
    summary.put("newServicesList", new io.vertx.core.json.JsonArray(new ArrayList<>(getNewServices())));
    summary.put("permissionChangedList", new io.vertx.core.json.JsonArray(new ArrayList<>(getPermissionChangedServices())));
    summary.put("keyRotationList", new io.vertx.core.json.JsonArray(new ArrayList<>(getKeyRotationServices())));
    
    return summary;
  }
  
  /**
   * Get total count of all services processed
   */
  public int getTotalServiceCount()
  {
    Set<String> allServices = new HashSet<>();
    allServices.addAll(permissionChangedBundles.keySet());
    allServices.addAll(keyRotationBundles.keySet());
    allServices.addAll(newBundles.keySet());
    allServices.addAll(removedBundles.keySet());
    allServices.addAll(unchangedBundles.keySet());
    return allServices.size();
  }
  
  /**
   * Get count of services that actually changed
   */
  public int getChangeCount()
  {
    return getChangedServices().size();
  }
  
  /**
   * Check if a specific service has changes
   */
  public boolean hasServiceChanged(String serviceId)
  {
    return getChangedServices().contains(serviceId);
  }
  
  /**
   * Create a filtered result containing only specific services
   */
  public BundleChangeResult filterByServices(Set<String> serviceIds)
  {
    BundleChangeResult filtered = new BundleChangeResult();
    
    for (String serviceId : serviceIds)
    {
      ChangeType changeType = getChangeType(serviceId);
      ServiceBundle bundle = getBundleForService(serviceId);
      
      if (bundle != null)
      {
        switch (changeType)
        {
          case NEW:
            filtered.addNewBundle(serviceId, bundle);
            break;
          case PERMISSION_CHANGED:
            filtered.addPermissionChangedBundle(serviceId, bundle);
            break;
          case KEY_ROTATION:
            Set<String> rotatedTopics = getRotatedTopicsForService(serviceId);
            filtered.addKeyRotationBundle(serviceId, bundle, rotatedTopics);
            break;
          case COMBINED_CHANGE:
            Set<String> combinedTopics = getRotatedTopicsForService(serviceId);
            filtered.addCombinedChangeBundle(serviceId, bundle, combinedTopics);
            break;
          case REMOVED:
            filtered.addRemovedBundle(serviceId, bundle);
            break;
          case UNCHANGED:
            filtered.addUnchangedBundle(serviceId, bundle);
            break;
        }
      }
    }
    
    return filtered;
  }
  
  /**
   * Clear all results (useful for testing)
   */
  public void clear()
  {
    permissionChangedBundles.clear();
    keyRotationBundles.clear();
    newBundles.clear();
    removedBundles.clear();
    unchangedBundles.clear();
    rotatedTopicsByService.clear();
    serviceChangeTypes.clear();
  }
  
  /**
   * Enhanced change types that distinguish permission vs key changes
   */
  public enum ChangeType
  {
    NEW,                    // Completely new service
    PERMISSION_CHANGED,     // ACL permissions changed (triggers key exchange)
    KEY_ROTATION,          // Only encryption keys rotated (bundle update only)
    COMBINED_CHANGE,       // Both permissions and keys changed
    REMOVED,               // Service removed
    UNCHANGED,             // No changes
    UNKNOWN                // Unknown state
  }
  
  @Override
  public String toString()
  {
    return String.format("BundleChangeResult{permission=%d, keyRotation=%d, new=%d, removed=%d, unchanged=%d, total=%d}", 
                        permissionChangedBundles.size(), keyRotationBundles.size(), 
                        newBundles.size(), removedBundles.size(), unchangedBundles.size(), getTotalServiceCount());
  }
}