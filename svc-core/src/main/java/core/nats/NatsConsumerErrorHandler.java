package core.nats;

import java.util.concurrent.atomic.AtomicInteger;

import io.nats.client.Connection;
import io.nats.client.Message;
import io.nats.client.Subscription;
import io.nats.client.JetStreamApiException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.exceptions.TemporaryProcessingException;

public class NatsConsumerErrorHandler
{
  private static final Logger logger = LoggerFactory.getLogger(NatsConsumerErrorHandler.class);
  
  private AtomicInteger     errorCount           = new AtomicInteger(0);
  private long              lastErrorResetTime   = System.currentTimeMillis();
  private static final int  ERROR_THRESHOLD      = 10;
  private static final long ERROR_RESET_INTERVAL = 60000; // 1 minute
  
  public NatsConsumerErrorHandler()
  {
  }
  
  /**
   * Determines if an error is unrecoverable
   */
  public boolean isUnrecoverableError(Throwable t) 
  {
    // Define conditions for unrecoverable errors
    return t instanceof OutOfMemoryError 
        || t instanceof ThreadDeath
        || t instanceof LinkageError
        || (t instanceof JetStreamApiException && isConnectionRelatedError((JetStreamApiException) t))
        || errorCountExceedsThreshold();
  }

  private boolean isConnectionRelatedError(JetStreamApiException e)
  {
    // Check for connection-related JetStream errors
    return e.getErrorCode() == 10054 || // Connection timeout
           e.getErrorCode() == 10051 || // No servers available
           e.getMessage().toLowerCase().contains("connection");
  }

  public boolean errorCountExceedsThreshold() 
  {
    long currentTime = System.currentTimeMillis();

    if(currentTime - lastErrorResetTime > ERROR_RESET_INTERVAL) 
    {
      // Reset error count after the interval
      errorCount.set(0);
      lastErrorResetTime = currentTime;
    }
    
    return errorCount.incrementAndGet() > ERROR_THRESHOLD;
  }

  /**
   * Handles message processing failures for NATS JetStream
   */
  public void handleMessageProcessingFailure( Connection connection, Message msg, Throwable cause )
  {
    try 
    {
      if(cause instanceof TemporaryProcessingException) 
      {
        // For JetStream, we can use NAK to trigger redelivery
        msg.nak();
        logger.info("Message NAK'd for redelivery: {}", msg.getSubject());
      } 
      else 
      {
        // Send to dead letter queue and acknowledge
        NatsDLQueue.sendToDeadLetterQueue(connection, msg);
        msg.ack();
        logger.info("Unprocessable message sent to Dead Letter Queue and acknowledged: {}", msg.getSubject());
      }
    } 
    catch(Exception e) 
    {
      logger.error("Error handling message processing failure", e);
    }
  }
  
  /**
   * Handles message processing failures for NATS JetStream
   */
  public void handleMessageProcessingFailure( Connection connection, Subscription subscription, Message msg, Throwable cause )
  {
    try 
    {
      if( cause instanceof TemporaryProcessingException) 
      {
        // For JetStream, we can use NAK to trigger redelivery
        msg.nak();
        logger.info("Message NAK'd for redelivery: {}", msg.getSubject());
      } 
      else 
      {
        // Send to dead letter queue and acknowledge
        NatsDLQueue.sendToDeadLetterQueue(connection, msg);
        msg.ack();
        logger.info("Unprocessable message sent to Dead Letter Queue and acknowledged: {}", msg.getSubject());
      }
    } 
    catch(Exception e) 
    {
      logger.error("Error handling message processing failure", e);
    }
  }
  
}