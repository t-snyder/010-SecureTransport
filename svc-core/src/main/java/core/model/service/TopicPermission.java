package core.model.service;

import java.util.Map;

//import core.model.service.TopicKey;

/**
 * Topic access information with encryption keys - Note the key Duraton time is defined within
 * metadataConfig.json - Currently it is set to 6 hour duration and 3 hour rotation, so there 
 * will be 2 active keys.
 */
public class TopicPermission
{
  private final String  topicName;
  private final boolean producePermission;
  private final boolean consumePermission;

  private final Map<String, TopicKey> topicKeys;
  
  public TopicPermission( String serviceId, String topicName, boolean producePermission, 
                          boolean consumePermission, Map<String, TopicKey> topicKeys )
  {
    this.topicName         = topicName;
    this.producePermission = producePermission;
    this.consumePermission = consumePermission;
    this.topicKeys         = topicKeys;
  }

  // Getters
  public String  getTopicName()         { return topicName;         }
  public boolean getProducePermission() { return producePermission; }
  public boolean getConsumePermission() { return consumePermission; }
  
  public Map<String, TopicKey> getTopicKeys() { return topicKeys; }
  
  public TopicKey getKeyById( String keyId )
  {
    if( topicKeys != null && !topicKeys.isEmpty() )
      return topicKeys.get( keyId );
    
    return null;
  }
}
