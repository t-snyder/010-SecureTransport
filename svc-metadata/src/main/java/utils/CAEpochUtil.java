package utils;

import java.time.Instant;

/**
 * Utility for CA epoch calculations using RotationConfig values
 */
public class CAEpochUtil
{
  private static final long EPOCH_ZERO_MILLIS = 0L;

  private final RotationConfig rotationConfig;
  
  
  public CAEpochUtil( RotationConfig rotationConfig )
  {
    this.rotationConfig = rotationConfig;
  }
  
  /**
   * Returns the epoch number for the given instant using RotationConfig.
   */
  public long epochNumberForInstant( Instant instant )
  {
    long epochDurationMillis = rotationConfig.getIntCaTtl().toMillis();
    return (instant.toEpochMilli() - EPOCH_ZERO_MILLIS) / epochDurationMillis;
  }

  /**
   * Returns the start instant for the given epoch number.
   */
  public Instant epochStart(long epochNumber )
  {
    long epochDurationMillis = rotationConfig.getIntCaTtl().toMillis();
    return Instant.ofEpochMilli(EPOCH_ZERO_MILLIS + epochNumber * epochDurationMillis);
  }

  /**
   * Returns the expiry instant for the given epoch number.
   */
  public Instant epochExpiry( long epochNumber )
  {
    long validityMillis = rotationConfig.getIntCaTtl().toMillis() + rotationConfig.getRotationOverlap().toMillis();

    return epochStart( epochNumber ).plusMillis(validityMillis);
  }

  /**
   * Returns the rotation time for the given epoch (when to rotate before expiry).
   */
  public Instant epochRotationTime(long epochNumber )
  {
    return epochStart (epochNumber )
           .plus(  rotationConfig.getIntCaTtl() )
           .minus( rotationConfig.getRotationOverlap() );
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
}