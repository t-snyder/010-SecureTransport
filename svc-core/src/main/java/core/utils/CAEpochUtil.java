package core.utils;

import java.time.Duration;
import java.time.Instant;

/**
 * Utility for CA epoch calculations using RotationConfig values
 */
public class CAEpochUtil
{
  private static final long EPOCH_ZERO_MILLIS = 0L;

  private final String   env;
  private final Duration intCaTtl;
  private final Duration rotationOverlap;
  private final Duration checkInterval;
  private final int      maxCertsInBundle;
  
  public CAEpochUtil()
  {
    if( System.getenv( "ENVIRONMENT" ) != null )
         this.env = System.getenv( "ENVIRONMENT" );
    else this.env = "testing";
    
    if ("testing".equalsIgnoreCase( env ) || "integration".equalsIgnoreCase( env )) 
    {
      intCaTtl         = Duration.ofMinutes(20); // Very short CA lifetime for rapid testing
      rotationOverlap  = Duration.ofMinutes(15); // Rotate 15 min before expiry
      checkInterval    = Duration.ofMinutes(2);  // Check every 2 minutes
      maxCertsInBundle = 3;                      // Allow more certs in bundle for testing
    } 
    else if ("staging".equalsIgnoreCase( env )) 
    {
      intCaTtl         = Duration.ofMinutes(60); // Very short CA lifetime for rapid testing
      rotationOverlap  = Duration.ofMinutes(30); // Rotate 15 min before expiry
      checkInterval    = Duration.ofMinutes(3);  // Check every 2 minutes
      maxCertsInBundle = 3;                      // Allow more certs in bundle for testing
    }
    else 
    {
      intCaTtl         = Duration.ofMinutes(120); // Long-lived for production
      rotationOverlap  = Duration.ofMinutes(90);  // 24h overlap for safety
      checkInterval    = Duration.ofMinutes(10);  // Check every 10 minutes
      maxCertsInBundle = 3;                       // Allow more certs in bundle for testing
    }
  }
  
  /**
   * Returns the epoch number for the given instant using RotationConfig.
   */
  public long epochNumberForInstant( Instant instant )
  {
    long epochDurationMillis = getIntCaTtl().toMillis();
    return (instant.toEpochMilli() - EPOCH_ZERO_MILLIS) / epochDurationMillis;
  }

  /**
   * Returns the start instant for the given epoch number.
   */
  public Instant epochStart(long epochNumber )
  {
    long epochDurationMillis = getIntCaTtl().toMillis();
    return Instant.ofEpochMilli(EPOCH_ZERO_MILLIS + epochNumber * epochDurationMillis);
  }

  /**
   * Returns the expiry instant for the given epoch number.
   */
  public Instant epochExpiry( long epochNumber )
  {
    long validityMillis = getIntCaTtl().toMillis() + getRotationOverlap().toMillis();

    return epochStart( epochNumber ).plusMillis(validityMillis);
  }

  /**
   * Returns the rotation time for the given epoch (when to rotate before expiry).
   */
  public Instant epochRotationTime(long epochNumber )
  {
    return epochStart( epochNumber )
           .plus(  getIntCaTtl() )
           .minus( getRotationOverlap() );
  }

  /**
   * Check if rotation is needed for the current epoch.
   */
  public boolean isRotationNeeded(Instant now )
  {
    long    currentEpoch = epochNumberForInstant( now );
    Instant rotationTime = epochRotationTime( currentEpoch );

    return now.isAfter(rotationTime);
  }
    
  public String buildCaTTLString()
  {
    return intCaTtl.toMinutes() + "m";
  }

  // Getters
  public Duration getIntCaTtl()         { return intCaTtl;         }
  public Duration getRotationOverlap()  { return rotationOverlap;  }
  public Duration getCheckInterval()    { return checkInterval;    }
  public int      getMaxCertsInBundle() { return maxCertsInBundle; }
}