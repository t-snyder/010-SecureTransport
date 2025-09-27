package acl;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Configuration for a single topic
 */
public class TopicConfig
{
  private final String topicName;
  private final Set<String> producers = ConcurrentHashMap.newKeySet();
  private final Set<String> consumers = ConcurrentHashMap.newKeySet();
  
  public TopicConfig(String topicName)
  {
    this.topicName = topicName;
  }
  
  public void addProducer(String serviceId) { producers.add(serviceId); }
  public void removeProducer(String serviceId) { producers.remove(serviceId); }
  public void addConsumer(String serviceId) { consumers.add(serviceId); }
  public void removeConsumer(String serviceId) { consumers.remove(serviceId); }
  
  public String getTopicName() { return topicName; }
  public Set<String> getProducers() { return new HashSet<>(producers); }
  public Set<String> getConsumers() { return new HashSet<>(consumers); }
  
  public boolean isEmpty() { return producers.isEmpty() && consumers.isEmpty(); }
  
  public JsonObject toJson()
  {
    return new JsonObject()
        .put("topicName", topicName)
        .put("producers", new JsonArray(new ArrayList<>(producers)))
        .put("consumers", new JsonArray(new ArrayList<>(consumers)));
  }
  
  public static TopicConfig fromJson(JsonObject json)
  {
    TopicConfig config = new TopicConfig(json.getString("topicName"));
    
    JsonArray producersArray = json.getJsonArray("producers", new JsonArray());
    for (int i = 0; i < producersArray.size(); i++)
    {
      config.addProducer(producersArray.getString(i));
    }
    
    JsonArray consumersArray = json.getJsonArray("consumers", new JsonArray());
    for (int i = 0; i < consumersArray.size(); i++)
    {
      config.addConsumer(consumersArray.getString(i));
    }
    
    return config;
  }
}