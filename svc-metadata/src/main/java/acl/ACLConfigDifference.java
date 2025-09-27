package acl;

import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import acl.ServicesACLConfig.PermissionType;

/**
 * High-performance differential analysis for structured configurations
 * O(n) complexity instead of O(n²) string comparisons
 */
public class ACLConfigDifference
{
  private static final Logger LOGGER = LoggerFactory.getLogger(ACLConfigDifference.class);
  
  private final Set<PermissionChange> addedPermissions = new HashSet<>();
  private final Set<PermissionChange> removedPermissions = new HashSet<>();
  private final Set<String> addedTopics = new HashSet<>();
  private final Set<String> removedTopics = new HashSet<>();
  private final Set<String> addedServices = new HashSet<>();
  private final Set<String> removedServices = new HashSet<>();
  
  public ACLConfigDifference(ServicesACLConfig newConfig, ServicesACLConfig oldConfig)
  {
    LOGGER.info("Computing structured configuration differences");
    
    calculatePermissionDifferences(newConfig, oldConfig);
    calculateTopicDifferences(newConfig, oldConfig);
    calculateServiceDifferences(newConfig, oldConfig);
    
    LOGGER.info("Differences: {} permissions added, {} removed; {} topics added, {} removed; {} services added, {} removed",
               addedPermissions.size(), removedPermissions.size(),
               addedTopics.size(), removedTopics.size(),
               addedServices.size(), removedServices.size());
  }
  
  private void calculatePermissionDifferences(ServicesACLConfig newConfig, ServicesACLConfig oldConfig)
  {
    Set<PermissionChange> newPermissions = extractAllPermissions(newConfig);
    Set<PermissionChange> oldPermissions = extractAllPermissions(oldConfig);
    
    // Added permissions = in new but not in old
    addedPermissions.addAll(newPermissions);
    addedPermissions.removeAll(oldPermissions);
    
    // Removed permissions = in old but not in new
    removedPermissions.addAll(oldPermissions);
    removedPermissions.removeAll(newPermissions);
  }
  
  private void calculateTopicDifferences(ServicesACLConfig newConfig, ServicesACLConfig oldConfig)
  {
    Set<String> newTopics = newConfig.getAllTopics();
    Set<String> oldTopics = oldConfig.getAllTopics();
    
    addedTopics.addAll(newTopics);
    addedTopics.removeAll(oldTopics);
    
    removedTopics.addAll(oldTopics);
    removedTopics.removeAll(newTopics);
  }
  
  private void calculateServiceDifferences(ServicesACLConfig newConfig, ServicesACLConfig oldConfig)
  {
    Set<String> newServices = newConfig.getAllServices();
    Set<String> oldServices = oldConfig.getAllServices();
    
    addedServices.addAll(newServices);
    addedServices.removeAll(oldServices);
    
    removedServices.addAll(oldServices);
    removedServices.removeAll(newServices);
  }
  
  private Set<PermissionChange> extractAllPermissions(ServicesACLConfig config)
  {
    Set<PermissionChange> permissions = new HashSet<>();
    
    for (String serviceId : config.getAllServices())
    {
      for (String topicName : config.getTopicsForService(serviceId))
      {
        Set<PermissionType> access = config.getServiceTopicAccess(serviceId, topicName);
        
        for (PermissionType permType : access)
        {
          permissions.add(new PermissionChange(serviceId, topicName, permType));
        }
      }
    }
    
    return permissions;
  }
  
  // Getters
  public Set<PermissionChange> getAddedPermissions() { return new HashSet<>(addedPermissions); }
  public Set<PermissionChange> getRemovedPermissions() { return new HashSet<>(removedPermissions); }
  public Set<String> getAddedTopics() { return new HashSet<>(addedTopics); }
  public Set<String> getRemovedTopics() { return new HashSet<>(removedTopics); }
  public Set<String> getAddedServices() { return new HashSet<>(addedServices); }
  public Set<String> getRemovedServices() { return new HashSet<>(removedServices); }
  
  public boolean hasChanges()
  {
    return !addedPermissions.isEmpty() || !removedPermissions.isEmpty() ||
           !addedTopics.isEmpty() || !removedTopics.isEmpty() ||
           !addedServices.isEmpty() || !removedServices.isEmpty();
  }
  
  public Set<String> getAffectedServices()
  {
    Set<String> affected = new HashSet<>();
    addedPermissions.forEach(p -> affected.add(p.getServiceId()));
    removedPermissions.forEach(p -> affected.add(p.getServiceId()));
    affected.addAll(addedServices);
    affected.addAll(removedServices);
    return affected;
  }
  
  public Set<String> getAffectedTopics()
  {
    Set<String> affected = new HashSet<>(addedTopics);
    affected.addAll(removedTopics);
    addedPermissions.forEach(p -> affected.add(p.getTopicName()));
    removedPermissions.forEach(p -> affected.add(p.getTopicName()));
    return affected;
  }
  
  /**
   * Represents a single permission change
   */
  public static class PermissionChange
  {
    private final String serviceId;
    private final String topicName;
    private final PermissionType permissionType;
    
    public PermissionChange(String serviceId, String topicName, PermissionType permissionType)
    {
      this.serviceId = serviceId;
      this.topicName = topicName;
      this.permissionType = permissionType;
    }
    
    public String getServiceId() { return serviceId; }
    public String getTopicName() { return topicName; }
    public PermissionType getPermissionType() { return permissionType; }
    
    @Override
    public boolean equals(Object obj)
    {
      if (this == obj) return true;
      if (obj == null || getClass() != obj.getClass()) return false;
      
      PermissionChange that = (PermissionChange) obj;
      return Objects.equals(serviceId, that.serviceId) &&
             Objects.equals(topicName, that.topicName) &&
             permissionType == that.permissionType;
    }
    
    @Override
    public int hashCode()
    {
      return Objects.hash(serviceId, topicName, permissionType);
    }
    
    @Override
    public String toString()
    {
      return String.format("%s:%s:%s", serviceId, topicName, permissionType);
    }
  }
}