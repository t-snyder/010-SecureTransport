package acl;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
//import io.vertx.core.WorkerExecutor;

import java.util.*;
//import java.util.regex.Matcher;
//import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import acl.ServicesACLConfig.PermissionType;

/**
 * Declarative ACL parser - script defines complete desired state
 * Permissions not in script are automatically removed
 */
public class DeclarativeACLParser extends ServicesACLParser
{
  private static final Logger LOGGER = LoggerFactory.getLogger(DeclarativeACLParser.class);
  
  public DeclarativeACLParser(Vertx vertx)
  {
    super(vertx);
  }
  
  /**
   * Calculate what needs to be added/removed to reach desired state
   */
  public Future<DeclarativeChangeResult> calculateDeclarativeChanges(String newScript, ServicesACLConfig currentState)
  {
    return workerExecutor.executeBlocking(() -> {
      try
      {
        LOGGER.info("Calculating declarative ACL changes");
        
        // Parse new script to get desired state
        ServicesACLConfig desiredState = parseFromScript(newScript)
                                                  .toCompletionStage()
                                                  .toCompletableFuture()
                                                  .get();
        
        // Calculate what needs to be added and removed
        DeclarativeChangeResult changes = calculateStateChanges(currentState, desiredState);
        
        LOGGER.info("Declarative changes: {} to add, {} to remove, {} unchanged",
                   changes.getToAdd().size(), changes.getToRemove().size(), changes.getUnchanged().size());
        
        return changes;
      }
      catch (Exception e)
      {
        throw new RuntimeException("Failed to calculate declarative changes", e);
      }
    });
  }
  
  /**
   * Calculate the difference between current and desired state
   */
  private DeclarativeChangeResult calculateStateChanges(ServicesACLConfig currentState, ServicesACLConfig desiredState)
  {
    Set<PermissionEntry> currentPermissions = extractAllPermissions(currentState);
    Set<PermissionEntry> desiredPermissions = extractAllPermissions(desiredState);
    
    // Permissions to add = in desired but not in current
    Set<PermissionEntry> toAdd = new HashSet<>(desiredPermissions);
    toAdd.removeAll(currentPermissions);
    
    // Permissions to remove = in current but not in desired  
    Set<PermissionEntry> toRemove = new HashSet<>(currentPermissions);
    toRemove.removeAll(desiredPermissions);
    
    // Unchanged permissions = in both
    Set<PermissionEntry> unchanged = new HashSet<>(currentPermissions);
    unchanged.retainAll(desiredPermissions);
    
    return new DeclarativeChangeResult(toAdd, toRemove, unchanged, desiredState);
  }
  
  /**
   * Extract all permissions from a configuration
   */
  private Set<PermissionEntry> extractAllPermissions(ServicesACLConfig config)
  {
    Set<PermissionEntry> permissions = new HashSet<>();
    
    for (String serviceId : config.getAllServices())
    {
      for (String topicName : config.getTopicsForService(serviceId))
      {
        Set<PermissionType> access = config.getServiceTopicAccess(serviceId, topicName);
        
        for (PermissionType permType : access)
        {
          permissions.add(new PermissionEntry(serviceId, topicName, permType));
        }
      }
    }
    
    return permissions;
  }
  
  /**
   * Result of declarative change calculation
   */
  public static class DeclarativeChangeResult
  {
    private final Set<PermissionEntry> toAdd;
    private final Set<PermissionEntry> toRemove;
    private final Set<PermissionEntry> unchanged;
    private final ServicesACLConfig desiredState;
    
    public DeclarativeChangeResult(Set<PermissionEntry> toAdd, Set<PermissionEntry> toRemove, 
                                  Set<PermissionEntry> unchanged, ServicesACLConfig desiredState)
    {
      this.toAdd = new HashSet<>(toAdd);
      this.toRemove = new HashSet<>(toRemove);
      this.unchanged = new HashSet<>(unchanged);
      this.desiredState = desiredState;
    }
    
    public Set<PermissionEntry> getToAdd() { return new HashSet<>(toAdd); }
    public Set<PermissionEntry> getToRemove() { return new HashSet<>(toRemove); }
    public Set<PermissionEntry> getUnchanged() { return new HashSet<>(unchanged); }
    public ServicesACLConfig getDesiredState() { return desiredState; }
    
    public boolean hasChanges() { return !toAdd.isEmpty() || !toRemove.isEmpty(); }
    
    public Set<String> getAffectedServices()
    {
      Set<String> affected = new HashSet<>();
      toAdd.forEach(p -> affected.add(p.getServiceId()));
      toRemove.forEach(p -> affected.add(p.getServiceId()));
      return affected;
    }
    
    public Set<String> getAffectedTopics()
    {
      Set<String> affected = new HashSet<>();
      toAdd.forEach(p -> affected.add(p.getTopicName()));
      toRemove.forEach(p -> affected.add(p.getTopicName()));
      return affected;
    }
    
    @Override
    public String toString()
    {
      return String.format("DeclarativeChanges{add=%d, remove=%d, unchanged=%d}", 
                          toAdd.size(), toRemove.size(), unchanged.size());
    }
  }
  
  /**
   * Permission entry for comparison
   */
  public static class PermissionEntry
  {
    private final String serviceId;
    private final String topicName;
    private final PermissionType permissionType;
    
    public PermissionEntry(String serviceId, String topicName, PermissionType permissionType)
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
      
      PermissionEntry that = (PermissionEntry) obj;
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