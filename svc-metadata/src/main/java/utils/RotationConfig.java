package utils;

import java.time.Duration;

import core.model.ServiceCoreIF;
import helper.MetadataConfig;

/**
 * Environment-specific rotation configuration
 */
public class RotationConfig 
{
  private final Duration intCaTtl;
  private final Duration rotationOverlap;
  private final Duration checkInterval;
  private final boolean  testingMode;
  private final int      maxCertsInBundle;
  private final String   caCertStream = ServiceCoreIF.MetaDataClientCaCertStream;

  private RotationConfig( Duration intCaTtl, Duration rotationOverlap, 
                          Duration checkInterval, boolean testingMode, int maxCertsInBundle) 
  {
    this.intCaTtl         = intCaTtl;
    this.rotationOverlap  = rotationOverlap;
    this.checkInterval    = checkInterval;
    this.testingMode      = testingMode;
    this.maxCertsInBundle = maxCertsInBundle;
  }

  public static RotationConfig fromConfig( MetadataConfig config ) 
  {
    String environment = config.getEnvironment(); // Read from MetadataConfig.json
       
    if ("testing".equalsIgnoreCase(environment) || "integration".equalsIgnoreCase(environment)) 
    {
      return new RotationConfig(
          Duration.ofMinutes(20),  // Very short CA lifetime for rapid testing
          Duration.ofMinutes(15),  // Rotate 15 min before expiry
          Duration.ofMinutes(2),   // Check every 2 minutes
          true,                    // Testing mode
          3                        // Allow more certs in bundle for testing
          
      );
    } 
    else if ("staging".equalsIgnoreCase(environment)) 
    {
      return new RotationConfig(
          Duration.ofMinutes(60),  // Short but reasonable for staging
          Duration.ofMinutes(30),  // 90 min overlap
          Duration.ofMinutes(5),  // Check every 10 minutes
          false,                   // Production-like behavior
          3                        // Limited cert accumulation
      );
    }
    else 
    {
      return new RotationConfig(
          Duration.ofMinutes(120),    // Long-lived for production
          Duration.ofHours(90),    // 24h overlap for safety
          Duration.ofMinutes(10),  // Check every 30 minutes
          false,                   // Production mode
          3                        // Conservative cert count
      );
    }
  }

  // Getters
  public Duration getIntCaTtl()         { return intCaTtl;         }
  public Duration getRotationOverlap()  { return rotationOverlap;  }
  public Duration getCheckInterval()    { return checkInterval;    }
  public boolean  isTestingMode()       { return testingMode;      }
  public int      getMaxCertsInBundle() { return maxCertsInBundle; }
  public String   getCaCertStream()     { return caCertStream;     }
  
  public String buildCaTTLString()
  {
    return intCaTtl.toMinutes() + "m";
  }
  
  @Override
  public String toString() 
  {
    return String.format("RotationConfig{ttl=%dmin, overlap=%dmin, check=%dmin, testing=%s}", 
                          intCaTtl.toMinutes(), rotationOverlap.toMinutes(), 
                          checkInterval.toMinutes(), testingMode);
  }
}
