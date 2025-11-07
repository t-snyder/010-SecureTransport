package core.nats;

import core.handler.CertificateUpdateCallbackIF;
import core.nats.NatsTLSClient.GracefulMigrationCapable;
import core.utils.CaRotationWindowManager;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;

import io.nats.client.*;
import io.nats.client.JetStream;
import io.nats.client.JetStreamSubscription;
import io.nats.client.MessageHandler;
import io.nats.client.PushSubscribeOptions;

import io.nats.client.api.ConsumerConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Enhanced Consumer Pool Manager for NATS JetStream with Graceful Migration Support
 *
 * Now automatically registers any consumer requested/created so the pool can
 * proactively warm-up (recreate) them during graceful CA rotation. No external
 * registration is required by services.
 */
public class NatsConsumerPoolManager implements CertificateUpdateCallbackIF, GracefulMigrationCapable
{
  private static final Logger LOGGER = LoggerFactory.getLogger(NatsConsumerPoolManager.class);

  // Pool configuration
  private static final Duration CONSUMER_TTL              = Duration.ofMinutes(60);
  private static final Duration CLEANUP_INTERVAL          = Duration.ofMinutes(5);
  private static final Duration IDLE_CONNECTION_THRESHOLD = Duration.ofSeconds(30);
  private static final Duration DRAINAGE_CHECK_INTERVAL   = Duration.ofSeconds(5);

  // Core dependencies
  private final Vertx           vertx;
  private final NatsTLSClient   natsTlsClient;
  private final WorkerExecutor  workerExecutor;

  // Pool management: active pooled consumers
  private final ConcurrentHashMap<String, PooledConsumer> pool = new ConcurrentHashMap<>();

  // Registry of all consumers requested/created (automatically populated)
  private final ConcurrentHashMap<String, ConsumerDescriptor> registeredConsumers = new ConcurrentHashMap<>();

  // Certificate generation tracking
  private volatile long    currentCertificateGeneration = 1;
  private final AtomicLong generationCounter = new AtomicLong(1);

  // Graceful migration support
  private volatile boolean    migrationInProgress = false;
  private volatile long       migrationGeneration = 0;
  private volatile Connection newConnection       = null;
  private volatile long       drainageTimerId     = -1;

  // Metrics and monitoring
  private final AtomicLong    totalConsumersCreated  = new AtomicLong(0);
  private final AtomicLong    totalConsumersClosed   = new AtomicLong(0);
  private final AtomicInteger currentActiveConsumers = new AtomicInteger(0);
  private final AtomicLong    totalPoolHits          = new AtomicLong(0);
  private final AtomicLong    totalPoolMisses        = new AtomicLong(0);

  // Lifecycle management
  private volatile boolean isShutdown     = false;
  private long             cleanupTimerId = -1;

  public NatsConsumerPoolManager(Vertx vertx, NatsTLSClient natsTlsClient)
  {
    this.vertx         = vertx;
    this.natsTlsClient = natsTlsClient;
    this.workerExecutor = vertx.createSharedWorkerExecutor("nats-consumer-pool-manager", 4, 360000);

    LOGGER.info("NatsConsumerPoolManager initialized - TTL: {}min", CONSUMER_TTL.toMinutes());
  }

  /**
   * Start the consumer pool manager
   */
  public void start()
  {
    if (isShutdown)
    {
      throw new IllegalStateException("Cannot start - manager is shutdown");
    }

    // Start periodic cleanup
    cleanupTimerId = vertx.setPeriodic(CLEANUP_INTERVAL.toMillis(), this::performCleanup);

    LOGGER.info("NatsConsumerPoolManager started - cleanup interval: {}min", CLEANUP_INTERVAL.toMinutes());
  }

  /**
   * Get or create a pooled consumer for a subject and consumer name
   * Enhanced to support graceful migration and automatic registration.
   * Returns Future immediately and uses async operations
   */
  public Future<Subscription> getOrCreateConsumer(String subject, String consumerName,
                                                  MessageHandler handler)
  {
    if (isShutdown)
    {
      return Future.failedFuture(new IllegalStateException("Consumer pool manager is shutdown"));
    }

    if (subject == null || consumerName == null || handler == null)
    {
      return Future.failedFuture(new IllegalArgumentException("Subject, consumer name and handler must not be null"));
    }

    String key = generateConsumerKey(subject, consumerName);

    // Ensure registry records this consumer request (so migration will warm it up)
    // Use putIfAbsent to avoid overwriting existing descriptor/handler
    registeredConsumers.putIfAbsent(key, new ConsumerDescriptor(subject, consumerName, handler));

    // Determine which connection and generation to use
    Connection connectionToUse = migrationInProgress && newConnection != null ?
                                 newConnection : natsTlsClient.getConnectionForNewOperations();

    long generation = migrationInProgress ? migrationGeneration : currentCertificateGeneration;

    return getOrCreateConsumerWithConnection(key, subject, consumerName, handler, connectionToUse, generation);
  }

  /**
   * Get or create consumer with specific connection and generation
   * Made fully async to prevent thread blocking
   */
  private Future<Subscription> getOrCreateConsumerWithConnection(String key, String subject,
                                                                String consumerName,
                                                                MessageHandler handler,
                                                                Connection connection, long generation)
  {
    // Check if we have a valid consumer for this generation
    PooledConsumer pooled = pool.get(key);
    if (pooled != null && pooled.isValid(generation))
    {
      pooled.updateLastUsed();
      totalPoolHits.incrementAndGet();
      LOGGER.debug("Consumer pool HIT for key: {} - generation: {}", key, generation);
      // Ensure descriptor exists in registry (idempotent)
      registeredConsumers.putIfAbsent(key, new ConsumerDescriptor(subject, consumerName, handler));
      return Future.succeededFuture(pooled.subscription);
    }

    // Pool miss - create new consumer ASYNCHRONOUSLY
    totalPoolMisses.incrementAndGet();
    LOGGER.debug("Consumer pool MISS for key: {} - creating new consumer with generation: {}", key, generation);

    return createNewConsumerWithConnectionAsync(subject, consumerName, handler, connection, generation)
             .onSuccess(consumer ->
             {
               // Store in pool
               PooledConsumer newPooledConsumer = new PooledConsumer(consumer, generation);
               pool.put(key, newPooledConsumer);
               // Register descriptor so future migrations will warm-up this consumer
               registeredConsumers.putIfAbsent(key, new ConsumerDescriptor(subject, consumerName, handler));
               LOGGER.debug("Added new consumer to pool and registry: {} - generation: {}", key, generation);
             });
  }

  /**
   * Create new consumer with specific connection and generation
   * Made this properly async using vertx.executeBlocking with timeout
   * Enhanced error handling for consumer creation with rotation-aware logging
   */
  private Future<Subscription> createNewConsumerWithConnectionAsync( String subject, String consumerName, 
                                                                     MessageHandler handler, Connection connection, 
                                                                     long generation)
  {
    Promise<Subscription> promise = Promise.promise();

    vertx.executeBlocking(() -> 
    {
      try
      {
        if (connection == null || connection.getStatus() != Connection.Status.CONNECTED)
        {
          throw new RuntimeException("NATS Connection not available or not connected");
        }

        // For JetStream consumers, we need to create a durable consumer
        JetStream js = connection.jetStream();
//        JetStreamManagement jsm = connection.jetStreamManagement();

        // Create consumer configuration
        ConsumerConfiguration consumerConfig = ConsumerConfiguration.builder()
            .durable(consumerName)
            .deliverSubject(subject + ".deliver")
            .ackWait(Duration.ofSeconds(30))
            .maxDeliver(3)
            .build();

        // Create push subscription
        PushSubscribeOptions pushOptions = PushSubscribeOptions.builder()
            .configuration(consumerConfig)
            .build();

        JetStreamSubscription subscription = js.subscribe( subject, consumerName, pushOptions);//        subscription.setMessageHandler(handler);
       
        totalConsumersCreated.incrementAndGet();
        currentActiveConsumers.incrementAndGet();

        LOGGER.info("Created new NATS consumer for subject: {}, consumer: {} (generation: {})", 
                   subject, consumerName, generation);
        return subscription;
      } 
      catch (Exception e)
      {
        // Use enhanced rotation-aware error logging
        String errorMessage = String.format("Failed to create consumer for subject: %s, consumer: %s", 
                                           subject, consumerName);

        // Enhanced error suppression during rotation
        CaRotationWindowManager.logPulsarConnectionError(LOGGER, errorMessage, e);

        throw new RuntimeException("Consumer creation failed", e);
      }
    }).onComplete(ar -> {
      if (ar.succeeded())
      {
        promise.complete(ar.result());
      } 
      else
      {
        // Additional suppression for promise failures during rotation
        Throwable cause = ar.cause();
        if (!CaRotationWindowManager.shouldSuppressDuringRotation(cause))
        {
          LOGGER.error("Consumer creation promise failed for subject: {}, consumer: {}", subject, consumerName, cause);
        } 
        else
        {
          LOGGER.debug("Consumer creation failed during CA rotation (suppressed): {}", cause.getMessage());
        }
        promise.fail(cause);
      }
    });

    return promise.future();
  }

  // ===== GRACEFUL MIGRATION SUPPORT =====

  /**
   * Start graceful migration to new connection
   *
   * Now warms up all registered consumers on the new connection/generation.
   */
  @Override
  public void startGracefulMigration(Connection newConnection, long newGeneration)
  {
    this.newConnection = newConnection;
    this.migrationGeneration = newGeneration;
    this.migrationInProgress = true;

    LOGGER.info("Starting graceful migration - generation: {} -> {}", currentCertificateGeneration, newGeneration);

    // Start timer to gradually drain old connections
    startConnectionDraining();

    // Warm-up all registered consumers on the new connection/generation
    // ASYNCHRONOUSLY
    if (!registeredConsumers.isEmpty())
    {
      LOGGER.info("Warming up {} registered consumers for generation {}", registeredConsumers.size(), newGeneration);
      for (Map.Entry<String, ConsumerDescriptor> e : registeredConsumers.entrySet())
      {
        ConsumerDescriptor d = e.getValue();
        final String key = e.getKey();
        // Attempt to create consumer with the new connection and generation ASYNC
        getOrCreateConsumerWithConnection(key, d.subject, d.consumerName, d.handler, newConnection, newGeneration)
          .onSuccess(c -> {
            LOGGER.info("Warm-up: created/reused consumer for {} / {}", d.subject, d.consumerName);
          })
          .onFailure(err -> {
            LOGGER.warn("Warm-up: failed to create consumer for {} / {} - {}", d.subject, d.consumerName, err.getMessage());
          });
      }
    }
  }

  /**
   * Complete migration process
   */
  @Override
  public void completeMigration()
  {
    LOGGER.info("=== CONSUMER POOL MIGRATION COMPLETION ===");
    LOGGER.info("Completing graceful migration - generation: {} at {}", migrationGeneration, Instant.now());

    int activeConsumers          = pool.size();
    int registeredConsumerCount  = registeredConsumers.size();
    int oldGenerationConnections = getActiveOldGenerationConnections();

    LOGGER.info("Consumer Pool Status - Active: {}, Registered: {}, Old Generation: {}", 
               activeConsumers, registeredConsumerCount, oldGenerationConnections);

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

    LOGGER.info("Consumer Pool Migration Complete - All new connections using generation: {}", currentCertificateGeneration);
    LOGGER.info("=== CONSUMER POOL READY ===");
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

    return (int) pool.values()
                     .stream()
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
      if (!migrationInProgress) {
        vertx.cancelTimer(timerId);
        drainageTimerId = -1;
        return;
      }

      // Execute blocking draining logic off the event loop with timeout
      vertx.executeBlocking(() -> 
      {
        return drainIdleOldConnections();
      })
      .onComplete(ar -> 
      {
        if (ar.succeeded()) 
        {
          LOGGER.debug("Drained {} old connections", ar.result());
        } 
        else 
        {
          LOGGER.warn("Drain failed: {}", ar.cause().getMessage());
        }
      });
    });
  }
  
  /**
   * Close idle connections from old generation
   */
  private int drainIdleOldConnections()
  {
    Instant cutoff = Instant.now().minus(IDLE_CONNECTION_THRESHOLD);
    int drainedCount = 0;

    Iterator<Map.Entry<String, PooledConsumer>> iterator = pool.entrySet().iterator();
    while (iterator.hasNext())
    {
      Map.Entry<String, PooledConsumer> entry = iterator.next();
      PooledConsumer pooled = entry.getValue();

      // Close old generation connections that have been idle
      if (pooled.getCertificateGeneration() < migrationGeneration && pooled.getLastUsed().isBefore(cutoff))
      {
        iterator.remove();

        try
        {
          closeConsumer(pooled.subscription, "migration-drain");
          drainedCount++;
          LOGGER.debug("Drained idle old connection for consumer: {}", entry.getKey());
        } 
        catch (Exception e)
        {
          // Use rotation-aware logging for drain errors
          CaRotationWindowManager.logConnectionError(LOGGER, 
            String.format("Error draining consumer %s", entry.getKey()), e);
        }
      }
    }

    return drainedCount;
  }

  // ===== CERTIFICATE UPDATE CALLBACKS =====

  /**
   * Implementation of CertificateUpdateCallbackIF
   * Called when certificates are rotated (fallback for non-graceful rotation)
   * IMPROVED: Better error handling and recovery
   */
  public void onCertificateUpdated()
  {
    // If graceful migration is in progress, this is handled by the migration
    // process
    if (migrationInProgress)
    {
      LOGGER.info("Certificate update received during graceful migration - handled by migration process");
      return;
    }

    // Add delay and retry logic for the fallback path
    long newGeneration = generationCounter.incrementAndGet();
    long oldGeneration = currentCertificateGeneration;
    currentCertificateGeneration = newGeneration;

    LOGGER.warn("Using fallback certificate rotation path - this may indicate graceful migration failed");
    LOGGER.info("Certificate rotation detected - invalidating all consumers (generation: {} -> {})", 
               oldGeneration, newGeneration);

    int consumerCount = pool.size();

    // Start suppression window if not already active
    if (!CaRotationWindowManager.isWithinRotationWindow())
    {
      CaRotationWindowManager.markRotationStart();
      LOGGER.info("Started CA rotation window for fallback certificate rotation");
    }

    // Add a small delay to allow any in-flight operations to complete, then
    // process async
    vertx.setTimer(2000, timerId -> {
      vertx.executeBlocking(() -> {
        invalidateAllConsumers();

        // Optionally attempt to pre-warm critical consumers
        preWarmCriticalConsumers(newGeneration);

        return null;
      }).onComplete(ar -> {
        if (ar.succeeded())
        {
          LOGGER.info("Fallback certificate rotation complete - invalidated {} consumers", consumerCount);
        } 
        else
        {
          LOGGER.error("Fallback certificate rotation invalidation failed", ar.cause());
        }

        // End suppression window after a delay to allow connections to
        // stabilize
        vertx.setTimer(30000, id -> {
          CaRotationWindowManager.markRotationEnd();
          LOGGER.info("CA rotation window ended for fallback rotation");
        });
      });
    });
  }
  
  /**
   * Pre-warm critical consumers async to reduce recovery time
   */
  private void preWarmCriticalConsumers(long generation) 
  {
    // Pre-create consumers for critical subjects to reduce recovery time
    for (Map.Entry<String, ConsumerDescriptor> entry : registeredConsumers.entrySet()) 
    {
      ConsumerDescriptor desc = entry.getValue();
      try 
      {
        // Use async creation to prevent blocking
        createNewConsumerWithConnectionAsync(desc.subject, desc.consumerName, 
                                            desc.handler, natsTlsClient.getConnectionForNewOperations(), generation)
          .onSuccess(consumer -> {
            PooledConsumer pooledConsumer = new PooledConsumer(consumer, generation);
            pool.put(entry.getKey(), pooledConsumer);
            LOGGER.info("Pre-warmed critical consumer: {}", entry.getKey());
          })
          .onFailure(err -> {
            LOGGER.warn("Failed to pre-warm critical consumer {}: {}", entry.getKey(), err.getMessage());
          });
      } 
      catch (Exception e) 
      {
        LOGGER.warn("Failed to pre-warm critical consumer {}: {}", entry.getKey(), e.getMessage());
      }
    }
  }
 
  @Override
  public void onCertificateUpdateFailed(Exception error)
  {
    LOGGER.error("Consumer pool manager certificate update failed", error);
  }

  // ===== POOL MANAGEMENT =====

  /**
   * Invalidate all consumers (bulk operation for certificate rotation)
   */
  private void invalidateAllConsumers()
  {
    LOGGER.info("Invalidating all consumers due to certificate rotation");

    // Close all consumers and clear pool
    pool.forEach((key, pooled) ->
    {
      closeConsumer(pooled.subscription, "certificate-rotation");
    });

    pool.clear();
    LOGGER.info("All consumers invalidated due to certificate rotation");
  }

  /**
   * Periodic cleanup of expired consumers
   */
  private void performCleanup(Long timerId)
  {
    if (isShutdown)
    {
      return;
    }

    vertx.executeBlocking(() ->
    {
      try
      {
        Instant now = Instant.now();
        int closedCount = 0;

        Iterator<Map.Entry<String, PooledConsumer>> iterator = pool.entrySet().iterator();
        while (iterator.hasNext())
        {
          Map.Entry<String, PooledConsumer> entry = iterator.next();
          PooledConsumer pooledConsumer = entry.getValue();

          if (!pooledConsumer.isValid(currentCertificateGeneration) ||
              pooledConsumer.isExpired(now, CONSUMER_TTL))
          {
            iterator.remove();
            closeConsumer(pooledConsumer.subscription, "cleanup-expired");
            closedCount++;
          }
        }

        if (closedCount > 0)
        {
          LOGGER.info("Pool cleanup: closed {} expired consumers (remaining: {})", closedCount, pool.size());
        }
        else
        {
          LOGGER.debug("Pool cleanup: no expired consumers (active: {})", pool.size());
        }

        return null;
      }
      catch (Exception e)
      {
        LOGGER.error("Error during consumer pool cleanup", e);
        return null;
      }
    });
  }

  /**
   * Close a consumer gracefully
   */
  private void closeConsumer(Subscription subscription, String reason)
  {
    try
    {
      if (subscription != null && subscription.isActive())
      {
        subscription.unsubscribe();
      }
      totalConsumersClosed.incrementAndGet();
      currentActiveConsumers.decrementAndGet();
      LOGGER.debug("Closed consumer (reason: {})", reason);
    }
    catch (Exception e)
    {
      LOGGER.warn("Error closing consumer (reason: {}): {}", reason, e.getMessage());
    }
  }

  /**
   * Generate unique key for consumer based on subject and consumer name
   */
  private String generateConsumerKey(String subject, String consumerName)
  {
    return subject + "::" + consumerName;
  }

  // ===== MONITORING AND STATISTICS =====

  /**
   * Get pool statistics for monitoring
   */
  public ConsumerStatistics getStatistics()
  {
    return new ConsumerStatistics(
      pool.size(),
      currentActiveConsumers.get(),
      totalPoolHits.get(),
      totalPoolMisses.get(),
      totalConsumersCreated.get(),
      totalConsumersClosed.get(),
      currentCertificateGeneration,
      getActiveOldGenerationConnections(),
      migrationInProgress
    );
  }

  // ===== LIFECYCLE MANAGEMENT =====

  /**
   * Shutdown the consumer pool manager
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

    return vertx.executeBlocking(() ->
    {
      LOGGER.info("Shutting down NatsConsumerPoolManager...");

      // Close all consumers
      pool.forEach((key, pooled) -> {
        closeConsumer(pooled.subscription, "shutdown");
      });

      pool.clear();
      workerExecutor.close();

      LOGGER.info("NatsConsumerPoolManager shutdown complete - closed {} consumers",
                  totalConsumersClosed.get());
      return null;
    }).mapEmpty();
  }

  // ===== INNER CLASSES =====

  /**
   * Pooled consumer wrapper with metadata
   */
  private static class PooledConsumer
  {
    final Subscription subscription;
    final long generation;
    final Instant created = Instant.now();
    private volatile Instant lastUsed;

    PooledConsumer(Subscription subscription, long generation)
    {
      this.subscription = subscription;
      this.generation = generation;
      this.lastUsed = created;
    }

    public long getCertificateGeneration()
    {
      return generation;
    }

    public Instant getLastUsed()
    {
      return lastUsed;
    }

    public void updateLastUsed()
    {
      this.lastUsed = Instant.now();
    }

    public boolean isValid(long currentGeneration)
    {
      return generation == currentGeneration;
    }

    public boolean isExpired(Instant now, Duration ttl)
    {
      return lastUsed.plus(ttl).isBefore(now);
    }
  }

  /**
   * Descriptor for registered consumers (subject, consumerName, handler)
   */
  private static class ConsumerDescriptor
  {
    final String subject;
    final String consumerName;
    final MessageHandler handler;

    ConsumerDescriptor(String subject, String consumerName, MessageHandler handler)
    {
      this.subject = subject;
      this.consumerName = consumerName;
      this.handler = handler;
    }
  }

  /**
   * Consumer statistics for monitoring with migration support
   */
  public static class ConsumerStatistics
  {
    private final int poolSize;
    private final int activeConsumers;
    private final long totalPoolHits;
    private final long totalPoolMisses;
    private final long totalConsumersCreated;
    private final long totalConsumersClosed;
    private final long currentCertificateGeneration;
    private final int activeOldGenerationConnections;
    private final boolean migrationInProgress;

    public ConsumerStatistics(int poolSize, int activeConsumers, long totalPoolHits,
                             long totalPoolMisses, long totalConsumersCreated,
                             long totalConsumersClosed, long currentCertificateGeneration,
                             int activeOldGenerationConnections, boolean migrationInProgress)
    {
      this.poolSize = poolSize;
      this.activeConsumers = activeConsumers;
      this.totalPoolHits = totalPoolHits;
      this.totalPoolMisses = totalPoolMisses;
      this.totalConsumersCreated = totalConsumersCreated;
      this.totalConsumersClosed = totalConsumersClosed;
      this.currentCertificateGeneration = currentCertificateGeneration;
      this.activeOldGenerationConnections = activeOldGenerationConnections;
      this.migrationInProgress = migrationInProgress;
    }

    // Getters
    public int getPoolSize() { return poolSize; }
    public int getActiveConsumers() { return activeConsumers; }
    public long getTotalPoolHits() { return totalPoolHits; }
    public long getTotalPoolMisses() { return totalPoolMisses; }
    public long getTotalConsumersCreated() { return totalConsumersCreated; }
    public long getTotalConsumersClosed() { return totalConsumersClosed; }
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
        "ConsumerStats{pool=%d, active=%d, hits=%d, misses=%d, hit_ratio=%.2f%%, " +
        "gen=%d, oldGen=%d, migrating=%s}",
        poolSize, activeConsumers, totalPoolHits, totalPoolMisses, getHitRatio() * 100,
        currentCertificateGeneration, activeOldGenerationConnections, migrationInProgress
      );
    }
  }
}