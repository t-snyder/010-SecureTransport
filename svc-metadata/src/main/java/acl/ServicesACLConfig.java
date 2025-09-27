package acl;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Structured ACL configuration replacing string-based script processing
 * Optimized for fast lookups and differential processing at scale
 */
public class ServicesACLConfig
{
  private static final Logger LOGGER = LoggerFactory.getLogger(ServicesACLConfig.class);
  
  // Core configuration data with optimized indexes
  private final Map<String, TopicConfig> topics = new ConcurrentHashMap<>();
  private final Map<String, ServiceConfig> services = new ConcurrentHashMap<>();
  
  // Fast lookup indexes
  private final Map<String, Set<String>> topicToServices = new ConcurrentHashMap<>();
  private final Map<String, Set<String>> serviceToTopics = new ConcurrentHashMap<>();
  private final Map<String, Set<String>> serviceProduceTopics = new ConcurrentHashMap<>();
  private final Map<String, Set<String>> serviceConsumeTopics = new ConcurrentHashMap<>();
  
  // Version tracking
  private long configVersion;
  private String configHash;
  private Instant lastModified;
  
  public ServicesACLConfig()
  {
    this.configVersion = System.currentTimeMillis();
    this.lastModified = Instant.now();
    updateConfigHash();
  }
  
  /**
   * Add a permission to the configuration
   */
  public synchronized void addPermission(String serviceId, String topicName, PermissionType action)
  {
    validateInputs(serviceId, topicName, action);
    
    // Update core data
    TopicConfig topicConfig = topics.computeIfAbsent(topicName, TopicConfig::new);
    ServiceConfig serviceConfig = services.computeIfAbsent(serviceId, ServiceConfig::new);
    
    if (action == PermissionType.PRODUCE)
    {
      topicConfig.addProducer(serviceId);
      serviceConfig.addProduceTopic(topicName);
    }
    else if (action == PermissionType.CONSUME)
    {
      topicConfig.addConsumer(serviceId);
      serviceConfig.addConsumeTopic(topicName);
    }
    
    // Update indexes
    updateIndexes(serviceId, topicName, action, true);
    
    // Update version
    incrementVersion();
    
    LOGGER.debug("Added {} permission: {} -> {}", action, serviceId, topicName);
  }
  
  /**
   * Remove a permission from the configuration
   */
  public synchronized void removePermission(String serviceId, String topicName, PermissionType action)
  {
    validateInputs(serviceId, topicName, action);
    
    TopicConfig topicConfig = topics.get(topicName);
    ServiceConfig serviceConfig = services.get(serviceId);
    
    if (topicConfig != null && serviceConfig != null)
    {
      if (action == PermissionType.PRODUCE)
      {
        topicConfig.removeProducer(serviceId);
        serviceConfig.removeProduceTopic(topicName);
      }
      else if (action == PermissionType.CONSUME)
      {
        topicConfig.removeConsumer(serviceId);
        serviceConfig.removeConsumeTopic(topicName);
      }
      
      // Update indexes
      updateIndexes(serviceId, topicName, action, false);
      
      // Clean up empty configs
      cleanupEmptyConfigs(serviceId, topicName);
      
      // Update version
      incrementVersion();
      
      LOGGER.debug("Removed {} permission: {} -> {}", action, serviceId, topicName);
    }
  }
  
  /**
   * Get all topics a service has access to
   */
  public Set<String> getTopicsForService(String serviceId)
  {
    return serviceToTopics.getOrDefault(serviceId, Collections.emptySet());
  }
  
  /**
   * Get all services that have access to a topic
   */
  public Set<String> getServicesForTopic(String topicName)
  {
    return topicToServices.getOrDefault(topicName, Collections.emptySet());
  }
  
  /**
   * Get specific access type for service on topic
   */
  public Set<PermissionType> getServiceTopicAccess(String serviceId, String topicName)
  {
    Set<PermissionType> access = new HashSet<>();
    
    if (serviceProduceTopics.getOrDefault(serviceId, Collections.emptySet()).contains(topicName))
    {
      access.add(PermissionType.PRODUCE);
    }
    
    if (serviceConsumeTopics.getOrDefault(serviceId, Collections.emptySet()).contains(topicName))
    {
      access.add(PermissionType.CONSUME);
    }
    
    return access;
  }
  
  /**
   * Get all services
   */
  public Set<String> getAllServices()
  {
    return new HashSet<>(services.keySet());
  }
  
  /**
   * Get all topics
   */
  public Set<String> getAllTopics()
  {
    return new HashSet<>(topics.keySet());
  }
  
  /**
   * Calculate structural differences between configurations
   */
  public ACLConfigDifference calculateDifference(ServicesACLConfig other)
  {
    if (other == null)
    {
      return new ACLConfigDifference(this, new ServicesACLConfig());
    }
    
    return new ACLConfigDifference(this, other);
  }
  
  /**
   * Fast hash-based change detection
   */
  public boolean hasChangedSince(String otherHash)
  {
    return !Objects.equals(this.configHash, otherHash);
  }
  
  /**
   * Convert to JSON for storage/transport
   */
  public JsonObject toJson()
  {
    JsonObject json = new JsonObject()
        .put("configVersion", configVersion)
        .put("configHash", configHash)
        .put("lastModified", lastModified.toString());
    
    // Topics
    JsonObject topicsJson = new JsonObject();
    for (Map.Entry<String, TopicConfig> entry : topics.entrySet())
    {
      topicsJson.put(entry.getKey(), entry.getValue().toJson());
    }
    json.put("topics", topicsJson);
    
    // Services
    JsonObject servicesJson = new JsonObject();
    for (Map.Entry<String, ServiceConfig> entry : services.entrySet())
    {
      servicesJson.put(entry.getKey(), entry.getValue().toJson());
    }
    json.put("services", servicesJson);
    
    return json;
  }
  
  /**
   * Create from JSON
   */
  public static ServicesACLConfig fromJson(JsonObject json)
  {
    ServicesACLConfig config = new ServicesACLConfig();
    
    config.configVersion = json.getLong("configVersion", System.currentTimeMillis());
    config.configHash = json.getString("configHash");
    config.lastModified = Instant.parse(json.getString("lastModified", Instant.now().toString()));
    
    // Load topics
    JsonObject topicsJson = json.getJsonObject("topics", new JsonObject());
    for (String topicName : topicsJson.fieldNames())
    {
      TopicConfig topicConfig = TopicConfig.fromJson(topicsJson.getJsonObject(topicName));
      config.topics.put(topicName, topicConfig);
    }
    
    // Load services
    JsonObject servicesJson = json.getJsonObject("services", new JsonObject());
    for (String serviceId : servicesJson.fieldNames())
    {
      ServiceConfig serviceConfig = ServiceConfig.fromJson(servicesJson.getJsonObject(serviceId));
      config.services.put(serviceId, serviceConfig);
    }
    
    // Rebuild indexes
    config.rebuildIndexes();
    
    return config;
  }
  
  // Private helper methods
  private void updateIndexes(String serviceId, String topicName, PermissionType action, boolean add)
  {
    if (add)
    {
      topicToServices.computeIfAbsent(topicName, k -> ConcurrentHashMap.newKeySet()).add(serviceId);
      serviceToTopics.computeIfAbsent(serviceId, k -> ConcurrentHashMap.newKeySet()).add(topicName);
      
      if (action == PermissionType.PRODUCE)
      {
        serviceProduceTopics.computeIfAbsent(serviceId, k -> ConcurrentHashMap.newKeySet()).add(topicName);
      }
      else if (action == PermissionType.CONSUME)
      {
        serviceConsumeTopics.computeIfAbsent(serviceId, k -> ConcurrentHashMap.newKeySet()).add(topicName);
      }
    }
    else
    {
      Set<String> topicServices = topicToServices.get(topicName);
      if (topicServices != null)
      {
        topicServices.remove(serviceId);
        if (topicServices.isEmpty())
        {
          topicToServices.remove(topicName);
        }
      }
      
      Set<String> serviceTopics = serviceToTopics.get(serviceId);
      if (serviceTopics != null)
      {
        serviceTopics.remove(topicName);
        if (serviceTopics.isEmpty())
        {
          serviceToTopics.remove(serviceId);
        }
      }
      
      if (action == PermissionType.PRODUCE)
      {
        Set<String> produceTopics = serviceProduceTopics.get(serviceId);
        if (produceTopics != null)
        {
          produceTopics.remove(topicName);
          if (produceTopics.isEmpty())
          {
            serviceProduceTopics.remove(serviceId);
          }
        }
      }
      else if (action == PermissionType.CONSUME)
      {
        Set<String> consumeTopics = serviceConsumeTopics.get(serviceId);
        if (consumeTopics != null)
        {
          consumeTopics.remove(topicName);
          if (consumeTopics.isEmpty())
          {
            serviceConsumeTopics.remove(serviceId);
          }
        }
      }
    }
  }
  
  private void cleanupEmptyConfigs(String serviceId, String topicName)
  {
    TopicConfig topicConfig = topics.get(topicName);
    if (topicConfig != null && topicConfig.isEmpty())
    {
      topics.remove(topicName);
    }
    
    ServiceConfig serviceConfig = services.get(serviceId);
    if (serviceConfig != null && serviceConfig.isEmpty())
    {
      services.remove(serviceId);
    }
  }
  
  private void rebuildIndexes()
  {
    // Clear existing indexes
    topicToServices.clear();
    serviceToTopics.clear();
    serviceProduceTopics.clear();
    serviceConsumeTopics.clear();
    
    // Rebuild from core data
    for (Map.Entry<String, TopicConfig> topicEntry : topics.entrySet())
    {
      String topicName = topicEntry.getKey();
      TopicConfig topicConfig = topicEntry.getValue();
      
      for (String producer : topicConfig.getProducers())
      {
        updateIndexes(producer, topicName, PermissionType.PRODUCE, true);
      }
      
      for (String consumer : topicConfig.getConsumers())
      {
        updateIndexes(consumer, topicName, PermissionType.CONSUME, true);
      }
    }
  }
  
  private void validateInputs(String serviceId, String topicName, PermissionType action)
  {
    if (serviceId == null || serviceId.trim().isEmpty())
    {
      throw new IllegalArgumentException("Service ID cannot be null or empty");
    }
    if (topicName == null || topicName.trim().isEmpty())
    {
      throw new IllegalArgumentException("Topic name cannot be null or empty");
    }
    if (action == null)
    {
      throw new IllegalArgumentException("Permission action cannot be null");
    }
  }
  
  private void incrementVersion()
  {
    this.configVersion = System.currentTimeMillis();
    this.lastModified = Instant.now();
    updateConfigHash();
  }
  
  private void updateConfigHash()
  {
    try
    {
      // Create a deterministic hash based on content
      StringBuilder content = new StringBuilder();
      
      // Sort for deterministic ordering
      List<String> sortedTopics = new ArrayList<>(topics.keySet());
      Collections.sort(sortedTopics);
      
      for (String topic : sortedTopics)
      {
        TopicConfig config = topics.get(topic);
        content.append(topic).append(":");
        
        List<String> sortedProducers = new ArrayList<>(config.getProducers());
        Collections.sort(sortedProducers);
        content.append("P[").append(String.join(",", sortedProducers)).append("]");
        
        List<String> sortedConsumers = new ArrayList<>(config.getConsumers());
        Collections.sort(sortedConsumers);
        content.append("C[").append(String.join(",", sortedConsumers)).append("];");
      }
      
      java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(content.toString().getBytes());
      this.configHash = Base64.getEncoder().encodeToString(hash);
    }
    catch (Exception e)
    {
      LOGGER.error("Failed to update config hash", e);
      this.configHash = String.valueOf(System.currentTimeMillis());
    }
  }
  
  // Getters
  public long getConfigVersion() { return configVersion; }
  public String getConfigHash() { return configHash; }
  public Instant getLastModified() { return lastModified; }
  public int getTopicCount() { return topics.size(); }
  public int getServiceCount() { return services.size(); }
  
  public enum PermissionType
  {
    PRODUCE, CONSUME
  }
}