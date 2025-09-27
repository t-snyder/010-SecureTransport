package core.nats;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.nats.client.Connection;
import io.nats.client.JetStream;
import io.nats.client.JetStreamApiException;
import io.nats.client.JetStreamManagement;
import io.nats.client.Message;
import io.nats.client.MessageHandler;
import io.nats.client.PullSubscribeOptions;
import io.nats.client.JetStreamSubscription;
import io.nats.client.api.PublishAck;
import io.nats.client.api.StreamConfiguration;
import io.nats.client.api.StreamInfo;
import io.nats.client.api.StorageType;
import io.nats.client.api.ConsumerConfiguration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provide functionality to forward unprocessable messages to a NATS JetStream dead letter queue.
 * Includes stream management, message routing, and monitoring capabilities.
 */
public class NatsDLQueue
{
  private static final Logger logger = LoggerFactory.getLogger(NatsDLQueue.class);
  
  private static final String DLQ_STREAM_PREFIX = "DLQ_";
  private static final String DLQ_SUBJECT_SUFFIX = ".dlq";
  
  // Cache to track created streams to avoid repeated API calls
  private static final ConcurrentHashMap<String, Boolean> createdStreams = new ConcurrentHashMap<>();
  
  /**
   * Sends problematic messages to a dead letter queue using JetStream
   */
  public static void sendToDeadLetterQueue(Connection connection, Message msg)
  {
    try 
    {
      JetStream js = connection.jetStream();
      
      String originalSubject = msg.getSubject();
      String dlqSubject = originalSubject + DLQ_SUBJECT_SUFFIX;
      String dlqStreamName = DLQ_STREAM_PREFIX + sanitizeStreamName(originalSubject);
      
      // Ensure DLQ stream exists
      ensureDLQStreamExists(connection, dlqStreamName, dlqSubject);
      
      // Create headers with metadata
      Map<String, String> headers = new HashMap<>();
      if (msg.getHeaders() != null) 
      {
        msg.getHeaders().entrySet().forEach(entry -> 
          headers.put(entry.getKey(), String.join(",", entry.getValue()))
        );
      }
      
      headers.put("original-subject", originalSubject);
      headers.put("failure-timestamp", String.valueOf(System.currentTimeMillis()));
      headers.put("dlq-reason", "processing-failed");
      headers.put("original-message-size", String.valueOf(msg.getData().length));
      
      if (msg.getReplyTo() != null) 
      {
        headers.put("original-reply-to", msg.getReplyTo());
      }
      
      // Add JetStream metadata if available
      if (msg.metaData() != null) 
      {
        headers.put("original-stream", msg.metaData().getStream());
        headers.put("original-sequence", String.valueOf(msg.metaData().streamSequence()));
        headers.put("original-consumer-sequence", String.valueOf(msg.metaData().consumerSequence()));
      }
      
      // Publish to DLQ with headers
      io.nats.client.impl.Headers natsHeaders = new io.nats.client.impl.Headers();
      headers.forEach(natsHeaders::put);
      
      PublishAck ack = js.publish(dlqSubject, natsHeaders, msg.getData());
      
      logger.info("Message sent to DLQ: {} -> {} (seq: {})", 
                  originalSubject, dlqSubject, ack.getSeqno());
    } 
    catch(Exception e)
    {
      logger.error("Failed to send message to DLQ for subject: {}", msg.getSubject(), e);
    }
  }
  
  /**
   * Ensures the dead letter queue stream exists
   */
  private static void ensureDLQStreamExists(Connection connection, String streamName, String subject)
  {
    // Check cache first to avoid repeated API calls
    if (createdStreams.containsKey(streamName)) 
    {
      return;
    }
    
    try 
    {
      JetStreamManagement jsm = connection.jetStreamManagement();
      
      try 
      {
        // Check if stream already exists
        StreamInfo streamInfo = jsm.getStreamInfo(streamName);
        createdStreams.put(streamName, true);
        logger.debug("DLQ Stream already exists: {}", streamName);
        return;
      } 
      catch (JetStreamApiException e) 
      {
        // Stream doesn't exist if we get a 10059 error (stream not found)
        if (e.getErrorCode() != 10059) 
        {
          throw e; // Re-throw if it's a different error
        }
      }
      
      // Create stream configuration
      StreamConfiguration streamConfig = StreamConfiguration.builder()
          .name(streamName)
          .subjects(subject)
          .maxAge(Duration.ofDays(7)) // Retain DLQ messages for 7 days
          .maxMessages(100000) // Maximum number of messages in DLQ
          .maxBytes(10L * 1024 * 1024 * 1024) // 10GB max storage
          .storageType(StorageType.File)
          .replicas(1)
          .discardPolicy(io.nats.client.api.DiscardPolicy.Old) // Discard old messages when limits hit
          .build();
      
      StreamInfo streamInfo = jsm.addStream(streamConfig);
      createdStreams.put(streamName, true);
      logger.info("Created DLQ stream: {} for subject: {}", streamName, subject);
    } 
    catch (Exception e) 
    {
      logger.error("Failed to ensure DLQ stream exists: {} for subject: {}", streamName, subject, e);
    }
  }
  
  /**
   * Sanitizes subject name to be valid as a stream name
   */
  private static String sanitizeStreamName(String subject)
  {
    // Replace dots and other special characters with underscores
    // JetStream stream names have restrictions: no spaces, dots, or special chars except dash/underscore
    return subject.replaceAll("[^a-zA-Z0-9_-]", "_").toUpperCase();
  }
  
  /**
   * Create a pull subscriber for monitoring DLQ messages
   */
  public static JetStreamSubscription createDLQMonitor(Connection connection, String originalSubject, 
                                                      String consumerName) throws Exception
  {
    String dlqSubject = originalSubject + DLQ_SUBJECT_SUFFIX;
    String dlqStreamName = DLQ_STREAM_PREFIX + sanitizeStreamName(originalSubject);
    
    // Ensure stream exists
    ensureDLQStreamExists(connection, dlqStreamName, dlqSubject);
    
    JetStream js = connection.jetStream();
    
    // Create consumer configuration for DLQ monitoring
    ConsumerConfiguration consumerConfig = ConsumerConfiguration.builder()
        .durable(consumerName + "-dlq-monitor")
        .ackWait(Duration.ofMinutes(1))
        .maxDeliver(-1) // Unlimited redelivery for monitoring
        .build();
    
    // Create pull subscription for DLQ monitoring
    PullSubscribeOptions pullOptions = PullSubscribeOptions.builder()
        .stream(dlqStreamName)
        .configuration(consumerConfig)
        .build();
    
    JetStreamSubscription subscription = js.subscribe(dlqSubject, pullOptions);
    
    logger.info("Created DLQ monitor subscription for subject: {} -> {}", originalSubject, dlqSubject);
    
    return subscription;
  }
  
  /**
   * Create a message handler for processing DLQ messages (for replay/analysis)
   */
  public static MessageHandler createDLQProcessor(String originalSubject, 
                                                 Connection sourceConnection,
                                                 MessageReplayHandler replayHandler)
  {
    return (msg) -> {
      try 
      {
        logger.info("Processing DLQ message from subject: {} (original: {})", 
                   msg.getSubject(), originalSubject);
        
        // Extract original message metadata from headers
        Map<String, String> originalHeaders = new HashMap<>();
        if (msg.getHeaders() != null) 
        {
          msg.getHeaders().entrySet().forEach(entry -> 
            originalHeaders.put(entry.getKey(), String.join(",", entry.getValue()))
          );
        }
        
        String originalSubjectFromHeader = originalHeaders.get("original-subject");
        String failureTimestamp = originalHeaders.get("failure-timestamp");
        String dlqReason = originalHeaders.get("dlq-reason");
        
        logger.info("DLQ Message details - Original Subject: {}, Failure Time: {}, Reason: {}", 
                   originalSubjectFromHeader, failureTimestamp, dlqReason);
        
        // Allow custom replay logic
        if (replayHandler != null) 
        {
          boolean shouldReplay = replayHandler.shouldReplay(msg, originalHeaders);
          if (shouldReplay) 
          {
            replayHandler.replayMessage(sourceConnection, originalSubjectFromHeader, msg.getData(), originalHeaders);
            logger.info("Replayed DLQ message to original subject: {}", originalSubjectFromHeader);
          }
        }
        
        msg.ack();
      }
      catch (Exception e) 
      {
        logger.error("Error processing DLQ message: {}", e.getMessage(), e);
        msg.nak();
      }
    };
  }
  
  /**
   * Get DLQ statistics for a specific subject
   */
  public static DLQStatistics getDLQStatistics(Connection connection, String originalSubject) 
  {
    try 
    {
      String dlqStreamName = DLQ_STREAM_PREFIX + sanitizeStreamName(originalSubject);
      JetStreamManagement jsm = connection.jetStreamManagement();
      StreamInfo streamInfo = jsm.getStreamInfo(dlqStreamName);
      
      return new DLQStatistics(
        streamInfo.getConfiguration().getName(),
        streamInfo.getStreamState().getMsgCount(),
        streamInfo.getStreamState().getByteCount(),
        streamInfo.getStreamState().getFirstTime(),
        streamInfo.getStreamState().getLastTime()
      );
    }
    catch (Exception e) 
    {
      logger.error("Failed to get DLQ statistics for subject: {}", originalSubject, e);
      return new DLQStatistics("unknown", 0, 0, null, null);
    }
  }
  
  /**
   * Interface for custom message replay logic
   */
  public interface MessageReplayHandler 
  {
    boolean shouldReplay(Message dlqMessage, Map<String, String> originalHeaders);
    void replayMessage(Connection connection, String originalSubject, byte[] messageData, Map<String, String> originalHeaders);
  }
  
  /**
   * DLQ Statistics class
   */
  public static class DLQStatistics 
  {
    private final String streamName;
    private final long messageCount;
    private final long byteCount;
    private final java.time.ZonedDateTime firstMessageTime;
    private final java.time.ZonedDateTime lastMessageTime;
    
    public DLQStatistics(String streamName, long messageCount, long byteCount,
                        java.time.ZonedDateTime firstMessageTime, java.time.ZonedDateTime lastMessageTime) 
    {
      this.streamName = streamName;
      this.messageCount = messageCount;
      this.byteCount = byteCount;
      this.firstMessageTime = firstMessageTime;
      this.lastMessageTime = lastMessageTime;
    }
    
    // Getters
    public String getStreamName() { return streamName; }
    public long getMessageCount() { return messageCount; }
    public long getByteCount() { return byteCount; }
    public java.time.ZonedDateTime getFirstMessageTime() { return firstMessageTime; }
    public java.time.ZonedDateTime getLastMessageTime() { return lastMessageTime; }
    
    @Override
    public String toString() 
    {
      return String.format("DLQStats{stream=%s, messages=%d, bytes=%d, first=%s, last=%s}",
                          streamName, messageCount, byteCount, firstMessageTime, lastMessageTime);
    }
  }
}