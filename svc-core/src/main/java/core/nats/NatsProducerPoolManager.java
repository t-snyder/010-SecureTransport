package core.nats;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;

import java.time.Instant;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import io.nats.client.Connection;
import io.nats.client.JetStream;
import io.nats.client.api.PublishAck;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.CertificateUpdateCallbackIF;
import core.nats.NatsTLSClient.GracefulMigrationCapable;
import core.utils.CaRotationWindowManager;

/**
 * Enhanced Producer Pool Manager for NATS JetStream with Graceful Migration Support
 * 
 * Features:
 * - Certificate-aware JetStream context pooling with automatic invalidation
 * - Three-tier pool strategy (Hot/Warm/Cold creation)
 * - Graceful CA rotation with staged migration
 * - Integration with NatsTLSClient certificate rotation
 * - Bounded resource usage with intelligent cleanup
 * - Metrics and monitoring support
 * 
 * Certificate Lifecycle:
 * - Tracks certificate generation for each JetStream context
 * - Supports graceful migration during CA rotation
 * - Gradual drainage of old connections
 * - Lazy recreation with fresh certificates
 */
public class NatsProducerPoolManager implements CertificateUpdateCallbackIF, GracefulMigrationCapable
{
  private static final Logger LOGGER = LoggerFactory.getLogger(NatsProducerPoolManager.class);

  // Pool configuration
  private static final int      MAX_HOT_POOL_SIZE         = 50;  // Smaller than Pulsar since NATS is lighter
  private static final int      MAX_WARM_POOL_SIZE        = 100;
  private static final Duration HOT_POOL_TTL              = Duration.ofMinutes(10);
  private static final Duration WARM_POOL_TTL             = Duration.ofMinutes(60);
  private static final Duration CLEANUP_INTERVAL          = Duration.ofMinutes(5);
  private static final Duration IDLE_CONNECTION_THRESHOLD = Duration.ofSeconds(30);
  private static final Duration DRAINAGE_CHECK_INTERVAL   = Duration.ofSeconds(5);

  // Core dependencies
  private final Vertx           vertx;
  private final NatsTLSClient   natsTlsClient;
  private final WorkerExecutor  workerExecutor;

  // Pool management - NATS uses JetStream contexts per subject pattern
  private final ConcurrentHashMap<String, PooledJetStreamContext> hotPool = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, PooledJetStreamContext> warmPool = new ConcurrentHashMap<>();

  // Certificate generation tracking
  private volatile long    currentCertificateGeneration = 1;
  private final AtomicLong generationCounter = new AtomicLong(1);

  // Graceful migration support
  private volatile boolean    migrationInProgress = false;
  private volatile long       migrationGeneration = 0;
  private volatile Connection newConnection       = null;
  private volatile long       drainageTimerId     = -1;

  // Metrics and monitoring
  private final AtomicLong    totalSentMessages      = new AtomicLong(0);
  private final AtomicLong    totalPoolHits          = new AtomicLong(0);
  private final AtomicLong    totalPoolMisses        = new AtomicLong(0);
  private final AtomicLong    totalContextsCreated   = new AtomicLong(0);
  private final AtomicLong    totalContextsClosed    = new AtomicLong(0);
  private final AtomicInteger currentActiveContexts  = new AtomicInteger(0);

  // Lifecycle management
  private volatile boolean isShutdown     = false;
  private long             cleanupTimerId = -1;

  public NatsProducerPoolManager(Vertx vertx, NatsTLSClient natsTlsClient)
  {
    this.vertx         = vertx;
    this.natsTlsClient = natsTlsClient;
    this.workerExecutor = vertx.createSharedWorkerExecutor("nats-producer-pool-manager", 4, 360000);

    LOGGER.info("NatsProducerPoolManager initialized - Hot: {}, Warm: {}, Cleanup: {}min", 
                MAX_HOT_POOL_SIZE, MAX_WARM_POOL_SIZE, CLEANUP_INTERVAL.toMinutes());
  }

  /**
   * Start the producer pool manager
   */
  public void start()
  {
    if (isShutdown)
    {
      throw new IllegalStateException("Cannot start - manager is shutdown");
    }

    // Start periodic cleanup
    cleanupTimerId = vertx.setPeriodic(CLEANUP_INTERVAL.toMillis(), this::performCleanup);

    LOGGER.info("NatsProducerPoolManager started - cleanup interval: {}min", CLEANUP_INTERVAL.toMinutes());
  }

  /**
   * Send message to subject using pooled JetStream context
   * Main interface for service bundle notifications
   */
  public Future<Void> sendMessage(String subject, byte[] messageBytes, Map<String, String> properties)
  {
    if (isShutdown)
    {
      return Future.failedFuture(new IllegalStateException("Producer pool manager is shutdown"));
    }

    if (subject == null || subject.trim().isEmpty())
    {
      return Future.failedFuture(new IllegalArgumentException("Subject cannot be null or empty"));
    }

    if (messageBytes == null)
    {
      return Future.failedFuture(new IllegalArgumentException("Message bytes cannot be null"));
    }

    LOGGER.debug("Sending message to subject: {} ({} bytes)", subject, messageBytes.length);

    return getOrCreateJetStreamContext(subject)
             .compose(jetStream -> sendMessageWithJetStream(jetStream, subject, messageBytes, properties))
             .onSuccess(v -> 
              {
                totalSentMessages.incrementAndGet();
                LOGGER.debug("Message sent successfully to subject: {}", subject);
              })
             .onFailure(err -> 
              {
                LOGGER.error("Failed to send message to subject: {} - {}", subject, err.getMessage());
                // Invalidate context on send failure
                invalidateContextForSubject(subject);
              });
  }

  /**
   * Get or create JetStream context for subject with pool management
   * Enhanced to support graceful migration
   */
  public Future<JetStream> getOrCreateJetStreamContext(String subject)
  {
    // Determine which connection and generation to use
    Connection connectionToUse = migrationInProgress && newConnection != null ? 
                                 newConnection : natsTlsClient.getConnectionForNewOperations();
    
    long generation = migrationInProgress ? migrationGeneration : currentCertificateGeneration;
    
    return getOrCreateContextWithConnection(subject, connectionToUse, generation);
  }

  /**
   * Get or create JetStream context with specific connection and generation
   */
  private Future<JetStream> getOrCreateContextWithConnection(String subject, Connection connection, long generation)
  {
    return Future.future(promise -> 
    {
      // For NATS, we can use a single key since JetStream contexts are lightweight
      String contextKey = "jetstream"; // Could be subject-specific if needed
      
      // Check hot pool first
      PooledJetStreamContext pooledContext = hotPool.get(contextKey);
      if (pooledContext != null && pooledContext.isValid(generation))
      {
        pooledContext.updateLastUsed();
        totalPoolHits.incrementAndGet();
        LOGGER.debug("JetStream context pool HIT (hot) for generation: {}", generation);
        promise.complete(pooledContext.getJetStream());
        return;
      }

      // Check warm pool
      pooledContext = warmPool.remove(contextKey);
      if (pooledContext != null && pooledContext.isValid(generation))
      {
        pooledContext.updateLastUsed();
        // Move to hot pool
        if (hotPool.size() < MAX_HOT_POOL_SIZE)
        {
          hotPool.put(contextKey, pooledContext);
        } 
        else
        {
          // Hot pool full, evict least recently used
          evictLeastRecentlyUsedFromHot();
          hotPool.put(contextKey, pooledContext);
        }

        totalPoolHits.incrementAndGet();
        LOGGER.debug("JetStream context pool HIT (warm->hot) for generation: {}", generation);
        promise.complete(pooledContext.getJetStream());
        return;
      }

      // Pool miss - create new JetStream context
      totalPoolMisses.incrementAndGet();
      LOGGER.debug("JetStream context pool MISS - creating new context with generation: {}", generation);

      createNewJetStreamContextWithConnection(connection, generation).onSuccess(jetStream -> 
      {
        // Add to hot pool
        PooledJetStreamContext newPooledContext = new PooledJetStreamContext(jetStream, generation);

        if (hotPool.size() < MAX_HOT_POOL_SIZE)
        {
          hotPool.put(contextKey, newPooledContext);
        } 
        else
        {
          // Hot pool full, evict least recently used
          evictLeastRecentlyUsedFromHot();
          hotPool.put(contextKey, newPooledContext);
        }

        promise.complete(jetStream);
      })
      .onFailure(promise::fail);
    });
  }

  /**
   * Create new JetStream context with specific connection and generation
   */
  private Future<JetStream> createNewJetStreamContextWithConnection(Connection connection, long generation)
  {
      return workerExecutor.executeBlocking(() -> {
          try
          {
              if (connection == null || connection.getStatus() != Connection.Status.CONNECTED)
              {
                  throw new RuntimeException("NATS Connection not available or not connected");
              }

              JetStream jetStream = connection.jetStream();

              totalContextsCreated.incrementAndGet();
              currentActiveContexts.incrementAndGet();

              LOGGER.info("Created new JetStream context (generation: {})", generation);
              return jetStream;
          } 
          catch (Exception e)
          {
              // Use rotation window manager for appropriate logging
              CaRotationWindowManager.logConnectionError(LOGGER, 
                  "Failed to create JetStream context", e);
              throw new RuntimeException("JetStream context creation failed", e);
          }
      });
  }  
  
  /**
   * Send message using specific JetStream context
   */
  public Future<Void> sendMessageWithJetStream(JetStream jetStream, String subject, byte[] payload, Map<String, String> headers)
  {
    Promise<Void> promise = Promise.promise();
    
    try
    {
      if (headers == null || headers.isEmpty())
      {
        // Simple publish without headers
        PublishAck ack = jetStream.publish(subject, payload);
        LOGGER.debug("Message published to {}, ack seq: {}", subject, ack.getSeqno());
        promise.complete();
      }
      else
      {
        // Publish with headers
        io.nats.client.impl.Headers natsHeaders = new io.nats.client.impl.Headers();
        headers.forEach(natsHeaders::put);
        
        PublishAck ack = jetStream.publish(subject, natsHeaders, payload);
        LOGGER.debug("Message with headers published to {}, ack seq: {}", subject, ack.getSeqno());
        promise.complete();
      }
    }
    catch (Exception e)
    {
      LOGGER.error("Failed to publish message to subject: {}", subject, e);
      promise.fail(e);
    }
    
    return promise.future();
  }

  // ===== GRACEFUL MIGRATION SUPPORT =====

  /**
   * Start graceful migration to new connection
   */
  @Override
  public void startGracefulMigration(Connection newConnection, long newGeneration)
  {
    this.newConnection       = newConnection;
    this.migrationGeneration = newGeneration;
    this.migrationInProgress = true;
    
    LOGGER.info("Starting graceful migration - generation: {} -> {}", currentCertificateGeneration, newGeneration);
    
    // Start timer to gradually drain old connections
    startConnectionDraining();
  }

  /**
   * Complete migration process
   */
  @Override
  public void completeMigration()
  {
      LOGGER.info("=== NATS PRODUCER POOL MIGRATION COMPLETION ===");
      LOGGER.info("Completing graceful migration - generation: {} at {}", migrationGeneration, Instant.now());
      
      int activeContexts = hotPool.size() + warmPool.size();
      int oldGenerationConnections = getActiveOldGenerationConnections();
      
      LOGGER.info("Producer Pool Status - Active: {}, Old Generation: {}", activeContexts, oldGenerationConnections);
      
      migrationInProgress = false;
      currentCertificateGeneration = migrationGeneration;
      newConnection = null;
      
      // Cancel drainage timer if running
      if (drainageTimerId != -1)
      {
          vertx.cancelTimer(drainageTimerId);
          drainageTimerId = -1;
          LOGGER.info("Connection drainage timer cancelled");
      }
      
      LOGGER.info("Producer Pool Migration Complete - All new connections using generation: {}", 
                 currentCertificateGeneration);
      LOGGER.info("=== NATS PRODUCER POOL READY ===");
  }
  
  /**
   * Rollback migration on failure
   */
  @Override
  public void rollbackMigration()
  {
    LOGGER.warn("Rolling back graceful migration - generation: {}", migrationGeneration);
    
    migrationInProgress = false;
    newConnection       = null;
    migrationGeneration = 0;
    
    // Cancel drainage timer if running
    if (drainageTimerId != -1)
    {
      vertx.cancelTimer(drainageTimerId);
      drainageTimerId = -1;
    }
    
    LOGGER.info("Migration rollback completed - continuing with generation: {}", currentCertificateGeneration);
  }

  /**
   * Get count of active old generation connections
   */
  @Override
  public int getActiveOldGenerationConnections()
  {
    if (!migrationInProgress)
    {
      return 0;
    }
    
    return (int) Stream.concat(hotPool.values().stream(), warmPool.values().stream())
                      .filter(p -> p.getCertificateGeneration() < migrationGeneration)
                      .count();
  }

  /**
   * Start connection draining process
   */
  private void startConnectionDraining()
  {
    LOGGER.info("Starting connection drainage for migration");
    
    // Timer to periodically check and close idle old connections
    drainageTimerId = vertx.setPeriodic(DRAINAGE_CHECK_INTERVAL.toMillis(), timerId -> 
    {
      if (!migrationInProgress)
      {
        vertx.cancelTimer(timerId);
        drainageTimerId = -1;
        return;
      }
      
      int drainedCount = drainIdleOldConnections();
      int remainingOld = getActiveOldGenerationConnections();
      
      LOGGER.debug("Migration drainage: drained {}, remaining old: {}", drainedCount, remainingOld);
      
      if (remainingOld == 0)
      {
        LOGGER.info("All old connections drained - migration ready for completion");
        vertx.cancelTimer(timerId);
        drainageTimerId = -1;
      }
    });
  }

  /**
   * Close idle connections from old generation
   */
  private int drainIdleOldConnections()
  {
    Instant cutoff = Instant.now().minus(IDLE_CONNECTION_THRESHOLD);
    int drainedCount = 0;
    
    // Drain from hot pool
    Iterator<Map.Entry<String, PooledJetStreamContext>> hotIter = hotPool.entrySet().iterator();
    while (hotIter.hasNext())
    {
      Map.Entry<String, PooledJetStreamContext> entry = hotIter.next();
      PooledJetStreamContext pooled = entry.getValue();
      
      // Close old generation connections that have been idle
      if (pooled.getCertificateGeneration() < migrationGeneration && 
          pooled.getLastUsed().isBefore(cutoff))
      {
        hotIter.remove();
        closeJetStreamContext(pooled.getJetStream(), "migration-drain");
        drainedCount++;
        LOGGER.debug("Drained idle old connection from hot pool: {}", entry.getKey());
      }
    }
    
    // Drain from warm pool
    Iterator<Map.Entry<String, PooledJetStreamContext>> warmIter = warmPool.entrySet().iterator();
    while (warmIter.hasNext())
    {
      Map.Entry<String, PooledJetStreamContext> entry = warmIter.next();
      PooledJetStreamContext pooled = entry.getValue();
      
      // Close old generation connections that have been idle
      if (pooled.getCertificateGeneration() < migrationGeneration && 
          pooled.getLastUsed().isBefore(cutoff))
      {
        warmIter.remove();
        closeJetStreamContext(pooled.getJetStream(), "migration-drain");
        drainedCount++;
        LOGGER.debug("Drained idle old connection from warm pool: {}", entry.getKey());
      }
    }
    
    return drainedCount;
  }

  // ===== CERTIFICATE UPDATE CALLBACKS =====

  /**
   * Implementation of CertificateUpdateCallbackIF
   * Called when certificates are rotated (fallback for non-graceful rotation)
   */
  @Override
  public void onCertificateUpdated()
  {
    // If graceful migration is in progress, this is handled by the migration process
    if (migrationInProgress)
    {
      LOGGER.info("Certificate update received during graceful migration - handled by migration process");
      return;
    }
    
    long newGeneration = generationCounter.incrementAndGet();
    long oldGeneration = currentCertificateGeneration;
 
    currentCertificateGeneration = newGeneration;

    LOGGER.info("Certificate rotation detected - invalidating all JetStream contexts (generation: {} -> {})", 
                oldGeneration, newGeneration);

    // Count contexts to be invalidated
    int hotCount  = hotPool.size();
    int warmCount = warmPool.size();

    // Perform bulk invalidation
    workerExecutor.executeBlocking(() -> 
    {
      invalidateAllContexts();
      return null;
    })
    .onComplete(ar -> 
     {
       if (ar.succeeded())
       {
         LOGGER.info("Certificate rotation complete - invalidated {} hot + {} warm contexts", hotCount, warmCount);
       } 
       else
       {
         LOGGER.error("Certificate rotation invalidation failed", ar.cause());
       }
     });
  }

  @Override
  public void onCertificateUpdateFailed(Exception error)
  {
    LOGGER.error("Certificate update failed - JetStream contexts may use stale certificates", error);
  }

  // ===== POOL MANAGEMENT =====

  /**
   * Invalidate all JetStream contexts (bulk operation for certificate rotation)
   */
  private void invalidateAllContexts()
  {
    LOGGER.info("Invalidating all JetStream contexts due to certificate rotation");

    // Gracefully close all contexts
    List<PooledJetStreamContext> allContexts = new ArrayList<>();
    allContexts.addAll(hotPool.values());
    allContexts.addAll(warmPool.values());

    // Clear pools first to prevent new usage
    hotPool.clear();
    warmPool.clear();

    // Close all contexts gracefully (note: JetStream contexts don't need explicit closing)
    for (PooledJetStreamContext pooledContext : allContexts)
    {
      closeJetStreamContext(pooledContext.getJetStream(), "certificate-rotation");
    }

    LOGGER.info("Invalidated {} JetStream contexts for certificate rotation", allContexts.size());
  }

  /**
   * Invalidate JetStream context for specific subject (error handling)
   */
  private void invalidateContextForSubject(String subject)
  {
    String contextKey = "jetstream"; // Using single key for now
    
    PooledJetStreamContext removed = hotPool.remove(contextKey);
    if (removed == null)
    {
      removed = warmPool.remove(contextKey);
    }

    if (removed != null)
    {
      closeJetStreamContext(removed.getJetStream(), "send-failure");
      LOGGER.debug("Invalidated JetStream context due to send failure");
    }
  }

  /**
   * Evict least recently used context from hot pool
   */
  private void evictLeastRecentlyUsedFromHot()
  {
    String oldestKey = null;
    Instant oldestTime = Instant.now();

    for (Map.Entry<String, PooledJetStreamContext> entry : hotPool.entrySet())
    {
      if (entry.getValue().getLastUsed().isBefore(oldestTime))
      {
        oldestTime = entry.getValue().getLastUsed();
        oldestKey = entry.getKey();
      }
    }

    if (oldestKey != null)
    {
      PooledJetStreamContext evicted = hotPool.remove(oldestKey);
      if (evicted != null)
      {
        // Move to warm pool if there's space
        if (warmPool.size() < MAX_WARM_POOL_SIZE)
        {
          warmPool.put(oldestKey, evicted);
          LOGGER.debug("Evicted context from hot to warm pool: {}", oldestKey);
        }
        else
        {
          // Warm pool also full, close the context
          closeJetStreamContext(evicted.getJetStream(), "pool-eviction");
          LOGGER.debug("Evicted and closed JetStream context: {}", oldestKey);
        }
      }
    }
  }

  /**
   * Periodic cleanup of expired contexts
   */
  private void performCleanup(Long timerId)
  {
    if (isShutdown)
    {
      return;
    }

    workerExecutor.executeBlocking(() -> 
    {
      try
      {
        Instant now = Instant.now();
        int closedCount = 0;

        // Cleanup hot pool
        Iterator<Map.Entry<String, PooledJetStreamContext>> hotIter = hotPool.entrySet().iterator();
        while (hotIter.hasNext())
        {
          Map.Entry<String, PooledJetStreamContext> entry = hotIter.next();
          PooledJetStreamContext pooledContext = entry.getValue();

          if (!pooledContext.isValid(currentCertificateGeneration) || 
              pooledContext.isExpired(now, HOT_POOL_TTL))
          {
            hotIter.remove();

            // Move to warm pool if not expired and space available
            if (pooledContext.isValid(currentCertificateGeneration) && 
                !pooledContext.isExpired(now, WARM_POOL_TTL) && 
                warmPool.size() < MAX_WARM_POOL_SIZE)
            {
              warmPool.put(entry.getKey(), pooledContext);
              LOGGER.debug("Moved context from hot to warm pool: {}", entry.getKey());
            } 
            else
            {
              closeJetStreamContext(pooledContext.getJetStream(), "cleanup-expired");
              closedCount++;
            }
          }
        }

        // Cleanup warm pool
        Iterator<Map.Entry<String, PooledJetStreamContext>> warmIter = warmPool.entrySet().iterator();
        while (warmIter.hasNext())
        {
          Map.Entry<String, PooledJetStreamContext> entry = warmIter.next();
          PooledJetStreamContext pooledContext = entry.getValue();

          if (!pooledContext.isValid(currentCertificateGeneration) || 
              pooledContext.isExpired(now, WARM_POOL_TTL))
          {
            warmIter.remove();
            closeJetStreamContext(pooledContext.getJetStream(), "cleanup-expired");
            closedCount++;
          }
        }

        if (closedCount > 0)
        {
          LOGGER.info("Pool cleanup: closed {} expired contexts (hot: {}, warm: {})", 
                      closedCount, hotPool.size(), warmPool.size());
        } 
        else
        {
          LOGGER.debug("Pool cleanup: no expired contexts (hot: {}, warm: {})", 
                       hotPool.size(), warmPool.size());
        }

        return null;
      } 
      catch (Exception e)
      {
        LOGGER.error("Error during JetStream context pool cleanup", e);
        return null;
      }
    });
  }

  /**
   * Close a JetStream context gracefully
   * Note: JetStream contexts are lightweight and don't need explicit closing,
   * but we track metrics
   */
  private void closeJetStreamContext(JetStream jetStream, String reason)
  {
    try
    {
      // JetStream contexts are just wrappers around connections
      // The actual cleanup happens when the connection is closed
      totalContextsClosed.incrementAndGet();
      currentActiveContexts.decrementAndGet();
      LOGGER.debug("Closed JetStream context (reason: {})", reason);
    } 
    catch (Exception e)
    {
      LOGGER.warn("Error closing JetStream context (reason: {}): {}", reason, e.getMessage());
    }
  }

  // ===== MONITORING AND STATISTICS =====

  /**
   * Get pool statistics for monitoring
   */
  public PoolStatistics getStatistics()
  {
    return new PoolStatistics(
      hotPool.size(), 
      warmPool.size(), 
      currentActiveContexts.get(), 
      totalSentMessages.get(), 
      totalPoolHits.get(), 
      totalPoolMisses.get(), 
      totalContextsCreated.get(), 
      totalContextsClosed.get(), 
      currentCertificateGeneration,
      getActiveOldGenerationConnections(),
      migrationInProgress
    );
  }

  // ===== LIFECYCLE MANAGEMENT =====

  /**
   * Shutdown the producer pool manager
   */
  public Future<Void> shutdown()
  {
    if (isShutdown)
    {
      return Future.succeededFuture();
    }

    isShutdown = true;

    if (cleanupTimerId != -1)
    {
      vertx.cancelTimer(cleanupTimerId);
    }
    
    if (drainageTimerId != -1)
    {
      vertx.cancelTimer(drainageTimerId);
    }

    return workerExecutor.executeBlocking(() -> {
      LOGGER.info("Shutting down NatsProducerPoolManager...");

      // Close all contexts
      List<PooledJetStreamContext> allContexts = new ArrayList<>();
      allContexts.addAll(hotPool.values());
      allContexts.addAll(warmPool.values());

      hotPool.clear();
      warmPool.clear();

      for (PooledJetStreamContext pooledContext : allContexts)
      {
        closeJetStreamContext(pooledContext.getJetStream(), "shutdown");
      }

      workerExecutor.close();

      LOGGER.info("NatsProducerPoolManager shutdown complete - closed {} contexts", allContexts.size());
      return null;
    }).mapEmpty();
  }

  // ===== INNER CLASSES =====

  /**
   * Pooled JetStream context wrapper with metadata
   */
  private static class PooledJetStreamContext
  {
    private final JetStream jetStream;
    private final long certificateGeneration;
    private volatile Instant lastUsed;
    private final Instant created;

    public PooledJetStreamContext(JetStream jetStream, long certificateGeneration)
    {
      this.jetStream = jetStream;
      this.certificateGeneration = certificateGeneration;
      this.created = Instant.now();
      this.lastUsed = created;
    }

    public JetStream getJetStream()
    {
      return jetStream;
    }

    public long getCertificateGeneration()
    {
      return certificateGeneration;
    }

    public Instant getLastUsed()
    {
      return lastUsed;
    }

    public Instant getCreated()
    {
      return created;
    }

    public void updateLastUsed()
    {
      this.lastUsed = Instant.now();
    }

    public boolean isValid(long currentGeneration)
    {
      return certificateGeneration == currentGeneration;
    }

    public boolean isExpired(Instant now, Duration ttl)
    {
      return lastUsed.plus(ttl).isBefore(now);
    }
  }

  /**
   * Enhanced pool statistics for monitoring with migration support
   */
  public static class PoolStatistics
  {
    private final int hotPoolSize;
    private final int warmPoolSize;
    private final int activeContexts;
    private final long totalSentMessages;
    private final long totalPoolHits;
    private final long totalPoolMisses;
    private final long totalContextsCreated;
    private final long totalContextsClosed;
    private final long currentCertificateGeneration;
    private final int activeOldGenerationConnections;
    private final boolean migrationInProgress;

    public PoolStatistics(int hotPoolSize, int warmPoolSize, int activeContexts, 
                         long totalSentMessages, long totalPoolHits, long totalPoolMisses, 
                         long totalContextsCreated, long totalContextsClosed, 
                         long currentCertificateGeneration, int activeOldGenerationConnections,
                         boolean migrationInProgress)
    {
      this.hotPoolSize = hotPoolSize;
      this.warmPoolSize = warmPoolSize;
      this.activeContexts = activeContexts;
      this.totalSentMessages = totalSentMessages;
      this.totalPoolHits = totalPoolHits;
      this.totalPoolMisses = totalPoolMisses;
      this.totalContextsCreated = totalContextsCreated;
      this.totalContextsClosed = totalContextsClosed;
      this.currentCertificateGeneration = currentCertificateGeneration;
      this.activeOldGenerationConnections = activeOldGenerationConnections;
      this.migrationInProgress = migrationInProgress;
    }

    // Getters
    public int getHotPoolSize() { return hotPoolSize; }
    public int getWarmPoolSize() { return warmPoolSize; }
    public int getActiveContexts() { return activeContexts; }
    public long getTotalSentMessages() { return totalSentMessages; }
    public long getTotalPoolHits() { return totalPoolHits; }
    public long getTotalPoolMisses() { return totalPoolMisses; }
    public long getTotalContextsCreated() { return totalContextsCreated; }
    public long getTotalContextsClosed() { return totalContextsClosed; }
    public long getCurrentCertificateGeneration() { return currentCertificateGeneration; }
    public int getActiveOldGenerationConnections() { return activeOldGenerationConnections; }
    public boolean isMigrationInProgress() { return migrationInProgress; }

    public double getHitRatio()
    {
      long total = totalPoolHits + totalPoolMisses;
      return total > 0 ? (double)totalPoolHits / total : 0.0;
    }

    @Override
    public String toString()
    {
      return String.format(
        "PoolStats{hot=%d, warm=%d, active=%d, sent=%d, hits=%d, misses=%d, hit_ratio=%.2f%%, " +
        "gen=%d, oldGen=%d, migrating=%s}", 
        hotPoolSize, warmPoolSize, activeContexts, totalSentMessages, 
        totalPoolHits, totalPoolMisses, getHitRatio() * 100,
        currentCertificateGeneration, activeOldGenerationConnections, migrationInProgress
      );
    }
  }
}