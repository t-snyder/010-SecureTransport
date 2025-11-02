package core.exceptions;


/**
 * Thrown when a required encryption key for a topic/service cannot be found.
 */
public class KeyMissingException extends Exception
{
  private final String serviceId;
  private final String topic;
  private final String keyId;

  public KeyMissingException( String serviceId, String topic, String keyId, String message )
  {
    super( message );
    this.serviceId = serviceId;
    this.topic = topic;
    this.keyId = keyId;
  }

  public String getServiceId()
  {
    return serviceId;
  }

  public String getTopic()
  {
    return topic;
  }

  public String getKeyId()
  {
    return keyId;
  }
}