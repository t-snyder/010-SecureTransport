package core.utils;

import java.time.Duration;
import java.time.Instant;

/**
 * Utility for CA epoch calculations with configurable rotation timing.
 * 
 * Design:
 * - Rotation interval: How often to create new certificates (20 min prod, 20 min testing)
 * - Certificate validity = 4 × rotation interval (survives 4 rotations)
 * - Grace period = 1 × rotation interval (expired certs kept temporarily)
 * - Result: 4-5 valid intermediate certs in bundle at any time
 * 
 * Rotation happens at the START of each epoch.
 */
public class CAEpochUtil
{
  private static final long EPOCH_ZERO_MILLIS = 0L;

  private final String   env;
  private final Duration rotationInterval;  // How often to rotate
  private final Duration certificateTTL;    // How long certs are valid (4 × rotation)
  private final Duration gracePeriod;       // Keep expired certs for this long
  private final Duration checkInterval;     // How often to check for rotation
  private final int      maxCertsInBundle;  // Maximum certs to keep
  
  public CAEpochUtil()
  {
    if (System.getenv("ENVIRONMENT") != null)
         this.env = System.getenv("ENVIRONMENT");
    else this.env = "testing";
    
    if ("testing".equalsIgnoreCase(env) || "integration".equalsIgnoreCase(env)) 
    {
      // Rapid rotation for testing
      rotationInterval  = Duration.ofMinutes(20);  // New cert every 20 min
      certificateTTL    = Duration.ofMinutes(80);  // Cert valid for 80 min (4 × 20)
      gracePeriod       = Duration.ofMinutes(20);  // 20 min grace after expiry
      checkInterval     = Duration.ofMinutes(2);   // Check every 2 minutes
      maxCertsInBundle  = 5;                       // Allow up to 5 certs
    } 
    else if ("staging".equalsIgnoreCase(env)) 
    {
      // Moderate rotation for staging
      rotationInterval  = Duration.ofMinutes(10);  // New cert every 10 min
      certificateTTL    = Duration.ofMinutes(40);  // Cert valid for 40 min (4 × 10)
      gracePeriod       = Duration.ofMinutes(10);  // 10 min grace after expiry
      checkInterval     = Duration.ofMinutes(2);   // Check every 2 minutes
      maxCertsInBundle  = 5;                       // Allow up to 5 certs
    }
    else 
    {
      // Production settings
      rotationInterval  = Duration.ofMinutes(20);  // New cert every 20 min
      certificateTTL    = Duration.ofMinutes(80);  // Cert valid for 80 min (4 × 20)
      gracePeriod       = Duration.ofMinutes(20);  // 20 min grace after expiry
      checkInterval     = Duration.ofMinutes(5);   // Check every 5 minutes
      maxCertsInBundle  = 5;                       // Allow up to 5 certs
    }
  }
  
  /**
   * Returns the epoch number for the given instant based on rotation interval.
   */
  public long epochNumberForInstant(Instant instant)
  {
    long epochDurationMillis = rotationInterval.toMillis();
    return (instant.toEpochMilli() - EPOCH_ZERO_MILLIS) / epochDurationMillis;
  }

  /**
   * Returns the start instant for the given epoch number.
   */
  public Instant epochStart(long epochNumber)
  {
    long epochDurationMillis = rotationInterval.toMillis();
    return Instant.ofEpochMilli(EPOCH_ZERO_MILLIS + epochNumber * epochDurationMillis);
  }

  /**
   * Returns the expiry instant for a certificate created at the given epoch.
   * This is when the certificate becomes invalid (not accounting for grace period).
   */
  public Instant epochExpiry(long epochNumber)
  {
    return epochStart(epochNumber).plus(certificateTTL);
  }

  /**
   * Returns the rotation time for the given epoch.
   * This is the start of the epoch - we rotate at epoch boundaries.
   */
  public Instant epochRotationTime(long epochNumber)
  {
    return epochStart(epochNumber);
  }

  /**
   * Returns the prune time for a certificate created at the given epoch.
   * This is when we can safely delete the certificate (expiry + grace period).
   */
  public Instant epochPruneTime(long epochNumber)
  {
    return epochExpiry(epochNumber).plus(gracePeriod);
  }

  /**
   * Check if rotation is needed at the current time.
   * 
   * Rotation is needed when we're in a new epoch that hasn't been rotated yet.
   * We compare the current epoch with the last rotated epoch.
   */
  public boolean isRotationNeeded(Instant now)
  {
    // This method is called with lastRotatedEpoch for comparison
    // The actual check is done in CaRotatorVert by comparing epochs
    // Here we just check if we're past the current epoch start
    long currentEpoch = epochNumberForInstant(now);
    Instant currentEpochStart = epochStart(currentEpoch);
    
    // We're in the rotation window if we're past (or at) the epoch start
    return !now.isBefore(currentEpochStart);
  }

  /**
   * Get the maximum age (in epochs) that a certificate should be kept.
   * This accounts for certificate TTL + grace period.
   */
  public long getMaxCertAgeInEpochs()
  {
    // Certificate lives for certificateTTL + gracePeriod
    // Divide by rotation interval to get number of epochs
    Duration totalLifetime = certificateTTL.plus(gracePeriod);
    return (totalLifetime.toMillis() + rotationInterval.toMillis() - 1) / rotationInterval.toMillis();
  }

  /**
   * Build Vault TTL string for certificate generation.
   * Format: "80m" for 80 minutes
   */
  public String buildCaTTLString()
  {
    return certificateTTL.toMinutes() + "m";
  }

  /**
   * Get human-readable description of current configuration.
   */
  public String getConfigDescription()
  {
    return String.format(
      "CA Rotation Config [%s]: rotation=%dm, cert_ttl=%dm, grace=%dm, check=%dm, max_certs=%d",
      env,
      rotationInterval.toMinutes(),
      certificateTTL.toMinutes(),
      gracePeriod.toMinutes(),
      checkInterval.toMinutes(),
      maxCertsInBundle
    );
  }

  // Getters
  public Duration getRotationInterval()  { return rotationInterval;  }
  public Duration getCertificateTTL()    { return certificateTTL;    }
  public Duration getGracePeriod()       { return gracePeriod;       }
  public Duration getCheckInterval()     { return checkInterval;     }
  public int      getMaxCertsInBundle()  { return maxCertsInBundle;  }
  public String   getEnvironment()       { return env;               }
  
  // Legacy compatibility
  @Deprecated
  public Duration getIntCaTtl() { return certificateTTL; }
  
  @Deprecated
  public Duration getRotationOverlap() { return gracePeriod; }
}