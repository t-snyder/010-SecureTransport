package acl;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Configuration for a single service
 */
public class ServiceConfig
{
  private final String serviceId;
  private final Set<String> produceTopics = ConcurrentHashMap.newKeySet();
  private final Set<String> consumeTopics = ConcurrentHashMap.newKeySet();
  
  public ServiceConfig(String serviceId)
  {
    this.serviceId = serviceId;
  }
  
  public void addProduceTopic(String topicName) { produceTopics.add(topicName); }
  public void removeProduceTopic(String topicName) { produceTopics.remove(topicName); }
  public void addConsumeTopic(String topicName) { consumeTopics.add(topicName); }
  public void removeConsumeTopic(String topicName) { consumeTopics.remove(topicName); }
  
  public String getServiceId() { return serviceId; }
  public Set<String> getProduceTopics() { return new HashSet<>(produceTopics); }
  public Set<String> getConsumeTopics() { return new HashSet<>(consumeTopics); }
  
  public boolean isEmpty() { return produceTopics.isEmpty() && consumeTopics.isEmpty(); }
  
  public JsonObject toJson()
  {
    return new JsonObject()
        .put("serviceId", serviceId)
        .put("produceTopics", new JsonArray(new ArrayList<>(produceTopics)))
        .put("consumeTopics", new JsonArray(new ArrayList<>(consumeTopics)));
  }
  
  public static ServiceConfig fromJson(JsonObject json)
  {
    ServiceConfig config = new ServiceConfig(json.getString("serviceId"));
    
    JsonArray produceArray = json.getJsonArray("produceTopics", new JsonArray());
    for (int i = 0; i < produceArray.size(); i++)
    {
      config.addProduceTopic(produceArray.getString(i));
    }
    
    JsonArray consumeArray = json.getJsonArray("consumeTopics", new JsonArray());
    for (int i = 0; i < consumeArray.size(); i++)
    {
      config.addConsumeTopic(consumeArray.getString(i));
    }
    
    return config;
  }
}