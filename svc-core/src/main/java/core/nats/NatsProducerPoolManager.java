package core.nats;

import io.nats.client.*;
import io.nats.client.impl.Headers;
import io.nats.client.impl.NatsMessage;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.CertificateUpdateCallbackIF;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * NATS Producer Pool Manager
 * Manages JetStream producer contexts with generation tracking
 * 
 * Removed: CaRotationWindowManager - errors are always logged
 */
public class NatsProducerPoolManager implements CertificateUpdateCallbackIF
{
  private static final Logger LOGGER = LoggerFactory.getLogger(NatsProducerPoolManager.class);

  private final Vertx vertx;
  private final NatsTLSClient natsTlsClient;

  // Generation tracking
  private final AtomicLong generationCounter = new AtomicLong(1);
  private volatile long currentCertificateGeneration = 1;

  // Pool management
  private final ConcurrentHashMap<Long, JetStream> hotPool = new ConcurrentHashMap<>();
  private final ConcurrentLinkedQueue<Long> warmPool = new ConcurrentLinkedQueue<>();

  private static final int MAX_HOT_POOL_SIZE = 10;
  private static final int MAX_WARM_POOL_SIZE = 5;

  public NatsProducerPoolManager(Vertx vertx, NatsTLSClient natsTlsClient)
  {
    this.vertx = vertx;
    this.natsTlsClient = natsTlsClient;
  }

  /**
   * Send message using producer pool
   */
  public Future<Void> sendMessage( String subject, byte[] data, Map<String, String> headers )
  {
    return vertx.executeBlocking(() -> {
      try
      {
        JetStream js = getOrCreateJetStream();
        
        if (headers != null && !headers.isEmpty())
        {
          // Build headers
          Headers natsHeaders = new Headers();
          headers.forEach(natsHeaders::add);
          
          // Create message with headers
          Message msg = NatsMessage.builder()
            .subject(subject)
            .data(data)
            .headers(natsHeaders)
            .build();
          
          js.publish(msg);
        }
        else
        {
          // Simple publish without headers
          js.publish(subject, data);
        }
        
        return null;
      }
      catch (Exception e)
      {
        // Always log errors (no suppression)
        if (isCertificateError(e))
        {
          LOGGER.error("Certificate error during publish to {}: {}", subject, e.getMessage());
        }
        else
        {
          LOGGER.error("Failed to publish to {}: {}", subject, e.getMessage(), e);
        }
        throw new RuntimeException("Publish failed", e);
      }
    });
  }
  
  /**
   * Get or create JetStream context for current generation
   */
  private JetStream getOrCreateJetStream() throws Exception
  {
    long currentGen = currentCertificateGeneration;

    // Check hot pool first
    JetStream js = hotPool.get(currentGen);
    if (js != null)
    {
      return js;
    }

    // Check warm pool
    Long warmGen = warmPool.poll();
    if (warmGen != null && warmGen == currentGen)
    {
      js = hotPool.get(warmGen);
      if (js != null)
      {
        return js;
      }
    }

    // Create new JetStream context
    Connection conn = natsTlsClient.getConnectionForNewOperations();
    if (conn == null)
    {
      throw new IllegalStateException("No NATS connection available");
    }

    js = conn.jetStream();
    
    // Add to hot pool
    hotPool.put(currentGen, js);
    
    // Manage pool size
    if (hotPool.size() > MAX_HOT_POOL_SIZE)
    {
      evictOldest();
    }

    LOGGER.debug("Created new JetStream context for generation {}", currentGen);
    return js;
  }

  /**
   * Invalidate all contexts - called during CA rotation
   */
  @Override
  public void onCertificateUpdated()
  {
    long newGeneration = generationCounter.incrementAndGet();
    currentCertificateGeneration = newGeneration;
    
    LOGGER.info("Producer pool: Certificate updated - new generation: {}", newGeneration);
    
    // Invalidate all contexts
    invalidateAllContexts();
  }

  @Override
  public void onCertificateUpdateFailed(Exception error)
  {
    LOGGER.error("Certificate update failed in producer pool", error);
  }

  /**
   * Invalidate all JetStream contexts
   */
  private void invalidateAllContexts()
  {
    int hotCount = hotPool.size();
    int warmCount = warmPool.size();
    
    hotPool.clear();
    warmPool.clear();
    
    LOGGER.info("Invalidated {} hot and {} warm producer contexts", hotCount, warmCount);
  }

  /**
   * Evict oldest context from pool
   */
  private void evictOldest()
  {
    if (hotPool.isEmpty())
    {
      return;
    }

    Long oldestGen = hotPool.keySet().stream()
      .min(Long::compareTo)
      .orElse(null);

    if (oldestGen != null && oldestGen < currentCertificateGeneration)
    {
      hotPool.remove(oldestGen);
      
      if (warmPool.size() < MAX_WARM_POOL_SIZE)
      {
        warmPool.offer(oldestGen);
      }
      
      LOGGER.debug("Evicted producer context for generation {}", oldestGen);
    }
  }

  /**
   * Check if exception is certificate-related
   */
  private boolean isCertificateError(Exception e)
  {
    if (e == null || e.getMessage() == null)
    {
      return false;
    }
    
    String msg = e.getMessage().toLowerCase();
    return msg.contains("certificate") ||
           msg.contains("ssl") ||
           msg.contains("tls") ||
           msg.contains("handshake");
  }

  /**
   * Shutdown pool
   */
  public void shutdown()
  {
    LOGGER.info("Shutting down producer pool");
    invalidateAllContexts();
  }

  /**
   * Get current generation
   */
  public long getCurrentGeneration()
  {
    return currentCertificateGeneration;
  }

  /**
   * Get pool stats
   */
  public Map<String, Object> getPoolStats()
  {
    Map<String, Object> stats = new HashMap<>();
    stats.put("currentGeneration", currentCertificateGeneration);
    stats.put("hotPoolSize", hotPool.size());
    stats.put("warmPoolSize", warmPool.size());
    return stats;
  }
}