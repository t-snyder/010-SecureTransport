package core.utils;

import java.util.List;

/**
 * Configuration class for key exchange service
 */
public class KeyExchangeConfig
{
  private final String       serviceId;
  private final long         rotationIntervalMins;
  private final String       consumerTopicSvcId;
  private final List<String> producerTopicSvcIds;
  private final long         expiryMinutes;

  public KeyExchangeConfig( String serviceId, long rotationIntervalMins, String consumerTopicSvcId, List<String> producerTopicSvcIds, long expiryMinutes )
  {
    this.serviceId            = serviceId;
    this.rotationIntervalMins = rotationIntervalMins;
    this.consumerTopicSvcId   = consumerTopicSvcId;
    this.producerTopicSvcIds  = producerTopicSvcIds;
    this.expiryMinutes        = expiryMinutes;
  }

  // Getters
  public String       getServiceId()            { return serviceId;               }
  public long         getRotationIntervalMins() { return rotationIntervalMins;    }
  public String       getConsumerTopicSvcId()   { return consumerTopicSvcId; }
  public List<String> getProducerTopicSvcIds()  { return producerTopicSvcIds;          }
  public long         getExpiryMinutes()        { return expiryMinutes;           }
}
