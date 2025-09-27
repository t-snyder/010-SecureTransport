package core.utils;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Enhanced utility class to manage CA rotation windows and suppress expected 
 * handshake errors during rotation periods with better pattern matching.
 */
public class CaRotationWindowManager
{
  private static final Logger LOGGER = LoggerFactory.getLogger(CaRotationWindowManager.class);

  private static final Duration DEFAULT_ROTATION_WINDOW = Duration.ofMinutes(3);
  private static final AtomicReference<Instant> lastRotationStart = new AtomicReference<>();
  private static final AtomicReference<Duration> rotationWindow = new AtomicReference<>(DEFAULT_ROTATION_WINDOW);

  // Patterns for identifying rotation-related errors
  private static final Pattern HANDSHAKE_ERROR_PATTERN = Pattern.compile(
    ".*(ssl|tls|handshake|certificate|connection.*closed|Connection already closed|ClosedChannelException).*",
    Pattern.CASE_INSENSITIVE
  );

  /**
   * Marks the start of a CA rotation period
   */
  public static void markRotationStart()
  {
    Instant now = Instant.now();
    lastRotationStart.set(now);
    LOGGER.info("CA rotation window started at {}, will suppress handshake errors for {}", 
                now, rotationWindow.get());
  }

  /**
   * Checks if we are currently within a CA rotation window
   * 
   * @return true if within rotation window, false otherwise
   */
  public static boolean isWithinRotationWindow()
  {
    Instant rotationStart = lastRotationStart.get();
    if (rotationStart == null)
    {
      return false;
    }

    Instant windowEnd = rotationStart.plus(rotationWindow.get());
    boolean withinWindow = Instant.now().isBefore(windowEnd);

    if (!withinWindow && LOGGER.isDebugEnabled())
    {
      LOGGER.debug("CA rotation window ended at {}", windowEnd);
    }

    return withinWindow;
  }

  /**
   * Explicitly ends the rotation window (optional - window will auto-expire)
   */
  public static void markRotationEnd()
  {
    Instant rotationStart = lastRotationStart.get();
    if (rotationStart != null)
    {
      LOGGER.info("CA rotation window manually ended after {}", 
                  Duration.between(rotationStart, Instant.now()));
      lastRotationStart.set(null);
    }
  }

  /**
   * Sets a custom rotation window duration
   * 
   * @param window the duration for which to suppress errors
   */
  public static void setRotationWindow(Duration window)
  {
    rotationWindow.set(window);
    LOGGER.info("CA rotation window duration set to {}", window);
  }

  /**
   * Gets the current rotation window duration
   * 
   * @return the current window duration
   */
  public static Duration getRotationWindow()
  {
    return rotationWindow.get();
  }

  /**
   * Checks if an error message appears to be rotation-related
   * 
   * @param message the error message to check
   * @return true if the message matches known rotation error patterns
   */
  public static boolean isRotationRelatedError(String message)
  {
    if (message == null) return false;
    return HANDSHAKE_ERROR_PATTERN.matcher(message).matches();
  }

  /**
   * Enhanced utility method to log handshake errors appropriately based on 
   * rotation window with pattern matching
   * 
   * @param logger the logger to use
   * @param message the error message
   * @param throwable the exception (optional)
   */
  public static void logHandshakeError(Logger logger, String message, Throwable throwable)
  {
    if (isWithinRotationWindow() && isRotationRelatedError(message))
    {
      logger.debug("Handshake error during CA rotation window (suppressed): {}", message);
      if (throwable != null && logger.isTraceEnabled())
      {
        logger.trace("Suppressed handshake error details:", throwable);
      }
    }
    else
    {
      if (throwable != null)
      {
        logger.error("Handshake error: {}", message, throwable);
      }
      else
      {
        logger.error("Handshake error: {}", message);
      }
    }
  }

  /**
   * Enhanced utility method to log connection errors appropriately based on 
   * rotation window with pattern matching
   * 
   * @param logger the logger to use
   * @param message the error message
   * @param throwable the exception (optional)
   */
  public static void logConnectionError(Logger logger, String message, Throwable throwable)
  {
    if (isWithinRotationWindow() && isRotationRelatedError(message))
    {
      logger.debug("Connection error during CA rotation window (suppressed): {}", message);
      if (throwable != null && logger.isTraceEnabled())
      {
        logger.trace("Suppressed connection error details:", throwable);
      }
    }
    else
    {
      if (throwable != null)
      {
        logger.warn("Connection error: {}", message, throwable);
      }
      else
      {
        logger.warn("Connection error: {}", message);
      }
    }
  }

  /**
   * Utility method specifically for Pulsar client errors that should be 
   * suppressed during rotation
   * 
   * @param logger the logger to use
   * @param message the error message
   * @param throwable the exception (optional)
   */
  public static void logPulsarConnectionError(Logger logger, String message, Throwable throwable)
  {
    // More aggressive suppression for known Pulsar rotation errors
    if (isWithinRotationWindow() && 
        (isRotationRelatedError(message) || 
         (throwable != null && isRotationRelatedError(throwable.getMessage()))))
    {
      logger.debug("Pulsar connection error during CA rotation window (suppressed): {}", message);
      if (throwable != null && logger.isTraceEnabled())
      {
        logger.trace("Suppressed Pulsar error details:", throwable);
      }
    }
    else
    {
      logConnectionError(logger, message, throwable);
    }
  }

  /**
   * Check if we should suppress specific exception types during rotation
   * 
   * @param throwable the exception to check
   * @return true if this exception should be suppressed during rotation
   */
  public static boolean shouldSuppressDuringRotation(Throwable throwable)
  {
    if (!isWithinRotationWindow() || throwable == null) return false;
    
    String className = throwable.getClass().getSimpleName();
    String message = throwable.getMessage();
    
    // Known rotation-related exceptions
    return className.contains("ClosedChannelException") ||
           className.contains("SSLHandshakeException") ||
           className.contains("PulsarClientException") ||
           (message != null && isRotationRelatedError(message));
  }
}