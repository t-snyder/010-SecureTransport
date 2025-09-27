package model;


/**
 * Defines policy parameters for cryptographic key rotation
 */
public class KeyRotationPolicy
{
  private final String serviceId;
  private final int    validityMinutes;
  private final int    warningThresholdMinutes;

  /**
   * Create a new key rotation policy
   *
   * @param serviceId       The service ID this policy applies to, or "*" for all services
   * @param validityMinutes  How long keys are valid in minutes
   * @param warningThresholdMinutes  How many minutes before expiry to start warning
   */
  public KeyRotationPolicy( String serviceId, int validityMinutes, int warningThresholdMinutes )
  {
    this.serviceId               = serviceId;
    this.validityMinutes         = validityMinutes;
    this.warningThresholdMinutes = warningThresholdMinutes;
  }

  /**
   * Get the service ID this policy applies to
   * 
   * @return Service ID or "*" for all services
   */
  public String getServiceId()
  {
    return serviceId;
  }

  /**
   * Get the validity period in minutes
   * 
   * @return Validity period in minutes
   */
  public int getValidityMinutes()
  {
    return validityMinutes;
  }

  /**
   * Get the warning threshold in minutes
   * 
   * @return Warning threshold in minutes
   */
  public int getWarningThresholdMinutes()
  {
    return warningThresholdMinutes;
  }

  /**
   * Check if this policy applies to the given service ID
   * 
   * @param targetServiceId
   *          Service ID to check
   * @return true if this policy applies to the service
   */
  public boolean appliesToService( String targetServiceId )
  {
    return "*".equals( serviceId ) || serviceId.equals( targetServiceId );
  }

  /**
   * Calculate when key rotation should occur
   * 
   * @return Minutes before expiry when rotation should occur
   */
  public int getRotationThresholdMinutes()
  {
    // Rotate when warning threshold is reached
    return warningThresholdMinutes;
  }

  @Override
  public String toString()
  {
    return "KeyRotationPolicy{" + "serviceId='" + serviceId + '\'' + ", validityMinutes=" + validityMinutes + ", warningThresholdMinutes=" + warningThresholdMinutes + '}';
  }
}