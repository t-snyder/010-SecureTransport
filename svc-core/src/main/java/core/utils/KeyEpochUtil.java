package core.utils;


import java.time.Instant;

/**
 * Utility for standardized epoch calculations across all topics.
 */
public class KeyEpochUtil
{
  // For testing
  public  static final long EPOCH_DURATION_MILLIS = 900000L;    // 15 minutes in milliseconds
  public  static final long KEY_VALIDITY_MILLIS   = 3600000L;   // 1 hours key valid
  private static final long EPOCH_ZERO_MILLIS     = 0L;         // 1970-01-01T00:00:00Z

  // Production
//  public  static final long EPOCH_DURATION_MILLIS = 3 * 60 * 60 * 1000L;  // 3 hours in milliseconds
//  public  static final long KEY_VALIDITY_MILLIS   = 6 * 60 * 60 * 1000L;    // 6 hours key valid
//  private static final long EPOCH_ZERO_MILLIS     = 0L; // 1970-01-01T00:00:00Z

  /**
   * Returns the epoch number for the given instant.
   */
  public static long epochNumberForInstant( Instant instant )
  {
    return ( instant.toEpochMilli() - EPOCH_ZERO_MILLIS ) / EPOCH_DURATION_MILLIS;
  }

  /**
   * Returns the start instant for the given epoch number.
   */
  public static Instant epochStart( long epochNumber )
  {
    return Instant.ofEpochMilli( EPOCH_ZERO_MILLIS + epochNumber * EPOCH_DURATION_MILLIS );
  }

  /**
   * Returns the expiry instant for the given epoch number.
   */
  public static Instant epochExpiry( long epochNumber )
  {
    return epochStart( epochNumber ).plusMillis( KEY_VALIDITY_MILLIS );
  }
}