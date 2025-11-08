package core.nats;

import io.nats.client.*;
import io.nats.client.api.ConsumerInfo;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.CertificateUpdateCallbackIF;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
//import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * NATS Consumer Pool Manager - Async Pull Consumer Implementation
 *
 * Manages JetStream pull consumers with:
 * - Async message processing (no blocking on worker threads)
 * - Non-blocking migration on certificate updates
 * - Per-consumer batch fetching loops
 * - Explicit ack/nak semantics
 * - Generation-based lifecycle tracking
 * 
 * @author t-snyder
 * @date 2025-11-04
 */
public class NatsConsumerPoolManager implements CertificateUpdateCallbackIF
{
  private static final Logger LOGGER = LoggerFactory.getLogger(NatsConsumerPoolManager.class);

  private final Vertx vertx;
  private final NatsTLSClient natsTlsClient;

  // Generation tracking
  private final AtomicLong generationCounter = new AtomicLong(1);
  private volatile long currentCertificateGeneration = 1;

  // Consumer tracking
  private final ConcurrentHashMap<String, ConsumerContext> consumerPool = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, ConsumerDescriptor> consumerRegistry = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, Long> pullTimers = new ConcurrentHashMap<>();

  /**
   * Cache of message sequences that were successfully processed but failed to ack
   */
  private final ConcurrentHashMap<String, ConcurrentHashMap<Long, Long>> failedAckCache = new ConcurrentHashMap<>();
  private static final long FAILED_ACK_TTL_MS = 300_000; // 5 minutes
  
  /**
   * Functional interface for async pull message handlers
   */
  @FunctionalInterface
  public interface AsyncPullMessageHandler
  {
    /**
     * Handle a message asynchronously
     * @param msg The NATS message
     * @return Future that completes when processing is done (success = ack, failure = nak)
     */
    Future<Void> handle(Message msg);
  }

  /**
   * Consumer context with generation and connection tracking
   */
  private static class ConsumerContext
  {
    final JetStreamSubscription subscription;
    final Connection connection;
    final long generation;

    ConsumerContext(JetStreamSubscription subscription, Connection connection, long generation)
    {
      this.subscription = subscription;
      this.connection = connection;
      this.generation = generation;
    }

    public boolean isSubscriptionActive()
    {
      if (subscription == null)
        return false;
      try
      {
        return subscription.isActive();
      }
      catch (Throwable t)
      {
        return true; // Conservative assumption
      }
    }
  }

  /**
   * Consumer descriptor for recreation
   */
  public static class ConsumerDescriptor
  {
    private final String streamName;
    private final String durableName;
    private final AsyncPullMessageHandler asyncHandler;
    private final int batchSize;
    private final long fetchTimeoutMs;
    private final long pullIntervalMs;
    private final boolean createdByManager;
    private final String expectedFilter;
    private final boolean autoCreate;

    public ConsumerDescriptor(String streamName, String durableName, AsyncPullMessageHandler asyncHandler,
                             int batchSize, long fetchTimeoutMs, long pullIntervalMs,
                             boolean createdByManager, String expectedFilter, boolean autoCreate)
    {
      this.streamName = streamName;
      this.durableName = durableName;
      this.asyncHandler = asyncHandler;
      this.batchSize = batchSize;
      this.fetchTimeoutMs = fetchTimeoutMs;
      this.pullIntervalMs = pullIntervalMs;
      this.createdByManager = createdByManager;
      this.expectedFilter = expectedFilter;
      this.autoCreate = autoCreate;
    }

    public String getStreamName() { return streamName; }
    public String getDurableName() { return durableName; }
    public AsyncPullMessageHandler getAsyncHandler() { return asyncHandler; }
    public int getBatchSize() { return batchSize; }
    public long getFetchTimeoutMs() { return fetchTimeoutMs; }
    public long getPullIntervalMs() { return pullIntervalMs; }
    public boolean isCreatedByManager() { return createdByManager; }
    public String getExpectedFilter() { return expectedFilter; }
    public boolean isAutoCreate() { return autoCreate; }
  }

  public NatsConsumerPoolManager(Vertx vertx, NatsTLSClient natsTlsClient)
  {
    this.vertx = vertx;
    this.natsTlsClient = natsTlsClient;
  }

  /**
   * Bind to an admin-created pull consumer and start fetching messages (ASYNC version)
   * 
   * @param streamName JetStream stream name
   * @param durableName Server-side durable consumer name
   * @param handler Async message handler (returns Future for ack/nak)
   * @param batchSize Number of messages to fetch per batch
   * @param fetchTimeoutMs Timeout for fetch operation (milliseconds)
   * @param pullIntervalMs Interval between fetch attempts (milliseconds)
   * @param expectedFilter Expected server-side consumer filter subject (nullable)
   * @param autoCreate If true, create the server-side consumer when missing
   * @return Future<JetStreamSubscription> bound subscription
   */
  public Future<JetStreamSubscription> bindPullConsumerAsync(
      String streamName,
      String durableName,
      AsyncPullMessageHandler handler,
      int batchSize,
      long fetchTimeoutMs,
      long pullIntervalMs,
      String expectedFilter,
      boolean autoCreate)
  {
    return vertx.executeBlocking(() -> {
      String key = streamName + ":" + durableName;
      long currentGen = currentCertificateGeneration;

      // Fast-path: reuse existing context for current generation
      ConsumerContext ctx = consumerPool.get(key);
      if (ctx != null && ctx.generation == currentGen)
      {
        try
        {
          if (ctx.isSubscriptionActive())
          {
            Connection conn = ctx.connection;
            if (conn != null && conn.getStatus() == Connection.Status.CONNECTED)
            {
              LOGGER.debug("Reusing pull consumer: {} (generation {})", key, currentGen);
              return ctx.subscription;
            }
          }
        }
        catch (Exception e)
        {
          LOGGER.info("Validation failed for existing pull consumer {}, recreating: {}", key, e.getMessage());
        }
      }

      // Get connection for new operations
      Connection conn = natsTlsClient.getConnectionForNewOperations();
      if (conn == null || conn.getStatus() != Connection.Status.CONNECTED)
      {
        throw new IllegalStateException("No NATS connection available for pull consumer binding");
      }

      LOGGER.info("Binding to pull consumer: stream={} durable={} (gen={}) expectedFilter='{}' autoCreate={}",
                 streamName, durableName, currentGen, expectedFilter, autoCreate);

      // Validate/create server-side consumer BEFORE making any local side-effects
      try
      {
        ensureServerConsumer(conn, streamName, durableName, expectedFilter, autoCreate);
      }
      catch (Exception e)
      {
        LOGGER.error("Server-side consumer validation/creation failed for {} on {}: {}",
                    durableName, streamName, e.getMessage());
        throw e;
      }

      // Register descriptor (admin-owned, never delete server-side)
      consumerRegistry.putIfAbsent(key,
        new ConsumerDescriptor(streamName, durableName, handler, batchSize, fetchTimeoutMs,
                              pullIntervalMs, false, expectedFilter, autoCreate));

      // Clean up old context if present (cancel timer and unsubscribe)
      if (ctx != null)
      {
        stopConsumer(key, ctx);
        consumerPool.remove(key);
      }

      // Bind to existing server-side durable consumer
      JetStream js = conn.jetStream();
      PullSubscribeOptions pullOpts = PullSubscribeOptions.builder()
        .stream(streamName)
        .durable(durableName)
        .build();

      JetStreamSubscription subscription = js.subscribe(null, pullOpts);

      // Start periodic pull loop with ASYNC handler
      long timerId = vertx.setPeriodic(pullIntervalMs,
        id -> pullMessagesAsync(key, subscription, handler, batchSize, fetchTimeoutMs));

      pullTimers.put(key, timerId);

      // Create and store context
      ConsumerContext newCtx = new ConsumerContext(subscription, conn, currentGen);
      consumerPool.put(key, newCtx);

      LOGGER.info("Bound to pull consumer: {} batchSize={} fetchTimeout={}ms pullInterval={}ms (generation {})",
                 key, batchSize, fetchTimeoutMs, pullIntervalMs, currentGen);

      return subscription;
    });
  }

  /**
   * Backwards-compatible overload that preserves the previous signature
   * Defaults: expectedFilter=null, autoCreate=false (strict mode)
   */
  public Future<JetStreamSubscription> bindPullConsumerAsync(
      String streamName,
      String durableName,
      AsyncPullMessageHandler handler,
      int batchSize,
      long fetchTimeoutMs,
      long pullIntervalMs)
  {
    return bindPullConsumerAsync(streamName, durableName, handler, batchSize,
                                 fetchTimeoutMs, pullIntervalMs, null, false);
  }

  /**
   * Pull messages from subscription in batches - ASYNC VERSION
   * No blocking - message handler returns Future for async processing
   */
  private void pullMessagesAsync( String key, JetStreamSubscription subscription, AsyncPullMessageHandler handler, int batchSize, long fetchTimeoutMs )
  {
    try
    {
      // Check if subscription is still active before attempting pull
      if (subscription == null || !subscription.isActive())
      {
        LOGGER.debug("Subscription {} is inactive - skipping pull", key);
        return;
      }
      
      List<Message> messages = subscription.fetch( batchSize, Duration.ofMillis( fetchTimeoutMs ) );

      if( messages.isEmpty() )
      {
        return;
      }

      LOGGER.debug( "Fetched {} messages for consumer {}", messages.size(), key );

      for( Message msg : messages )
      {
        final long streamSeq = msg.metaData().streamSequence();

        // Check if this message was already processed but failed to ack
        if( wasProcessedButFailedToAck( key, streamSeq ) )
        {
          LOGGER.info( "Message seq={} was already processed but failed to ack - acking without reprocessing", streamSeq );

          boolean ackSent = tryAck( msg, key, streamSeq );
          if( ackSent )
          {
            removeFromFailedAckCache( key, streamSeq );
            LOGGER.debug( "Successfully acked previously-processed message seq={}", streamSeq );
          }
          else
          {
            updateFailedAckCacheTimestamp( key, streamSeq );
            LOGGER.warn( "Message seq={} still cannot be acked - will retry on next redelivery", streamSeq );
          }

          continue; // Skip reprocessing
        }

        // Process message asynchronously (no in-flight tracking needed)
        handler.handle( msg ).onComplete( ar -> {
          if( ar.succeeded() )
          {
            // Processing succeeded - try to ack
            boolean ackSent = tryAck( msg, key, streamSeq );

            if( !ackSent )
            {
              // Processing succeeded but ack failed - add to cache
              addToFailedAckCache( key, streamSeq );
              LOGGER.warn( "Message seq={} processed successfully but ACK failed - added to cache", streamSeq );
            }
          }
          else
          {
            // Processing failed - nak for immediate redelivery
            LOGGER.error( "Message processing failed for consumer {} seq={}: {}", key, streamSeq, ar.cause() != null ? ar.cause().getMessage() : "unknown", ar.cause() );
            tryNak( msg, key, streamSeq );
          }
        } );
      }
    }
    catch( Exception e )
    {
      LOGGER.warn( "Pull failed for consumer {}: {}", key, e.getMessage() );
    }
  }
  
  /**
   * Stop a pull consumer (cancel timer and unsubscribe)
   * For pull consumers, there's no drain needed - just stop fetching and unsubscribe
   */
  private void stopConsumer(String key, ConsumerContext ctx)
  {
    if (ctx == null)
      return;

    LOGGER.debug("Stopping pull consumer: {} (gen {})", key, ctx.generation);

    // STEP 1: Cancel pull timer (stops fetching new messages)
    Long timerId = pullTimers.remove(key);
    if (timerId != null)
    {
      try
      {
        vertx.cancelTimer(timerId);
        LOGGER.debug("Cancelled pull timer for {}", key);
      }
      catch (Exception e)
      {
        LOGGER.debug("Failed to cancel timer for {}: {}", key, e.getMessage());
      }
    }

    // STEP 2: Unsubscribe (no drain needed for pull consumers)
    if (ctx.subscription != null)
    {
      try
      {
        ctx.subscription.unsubscribe();
        LOGGER.debug("Unsubscribed pull consumer: {}", key);
      }
      catch (Exception e)
      {
        LOGGER.debug("Unsubscribe failed for {}: {}", key, e.getMessage());
      }
    }
  }

  /**
   * Certificate update callback - trigger migration to new generation
   */
  @Override
  public void onCertificateUpdated()
  {
    long oldGeneration = currentCertificateGeneration;
    long newGeneration = generationCounter.incrementAndGet();
    currentCertificateGeneration = newGeneration;

    LOGGER.info("Consumer pool: Certificate updated - old gen: {}, new gen: {}", oldGeneration, newGeneration);

    migrateConsumersToNewGenerationAsync(oldGeneration, newGeneration).onComplete(ar -> {
      if (ar.failed())
      {
        LOGGER.warn("Consumer migration encountered errors: {}",
                   ar.cause() != null ? ar.cause().getMessage() : "unknown", ar.cause());
      }
      else
      {
        LOGGER.info("Consumer migration completed: gen {} → {}", oldGeneration, newGeneration);
      }
    });
  }

  @Override
  public void onCertificateUpdateFailed(Exception error)
  {
    LOGGER.error("Certificate update failed in consumer pool", error);
  }

  private Future<Void> migrateConsumersToNewGenerationAsync( long oldGen, long newGen )
  {
    Map<String, ConsumerDescriptor> descriptors = new HashMap<>( consumerRegistry );
    Map<String, ConsumerContext> oldConsumers = new HashMap<>( consumerPool );

    LOGGER.info( "Safe-fast migration: gen {} → gen {} ({} consumers)", oldGen, newGen, descriptors.size() );

    // NOTE: Timer stopping is performed by NatsTLSClient before it triggers the
    // pool recreation. Do NOT stop timers here to avoid duplicate blocking waits.

    if( descriptors.isEmpty() )
    {
      cleanupOldConsumers( oldConsumers, oldGen );
      return Future.succeededFuture();
    }

    // Rebind consumers in parallel with 2 max retries
    List<Future<JetStreamSubscription>> rebindFutures = descriptors.values().stream().map( desc -> rebindWithSmartRetry( desc, newGen, 2 ) ).collect( Collectors.toList() );

    return Future.all( rebindFutures ).compose( cf -> {
      int successCount = (int)rebindFutures.stream().filter( f -> f.result() != null ).count();

      LOGGER.info( "Migration complete: {} succeeded, {} failed", successCount, descriptors.size() - successCount );

      cleanupOldConsumers( oldConsumers, oldGen );

      if( successCount == 0 )
      {
        return Future.failedFuture( "All consumer rebinds failed" );
      }

      return Future.succeededFuture();
    } );
  }

  /**
   * Smart retry: Fast first attempt, single retry if needed
   */
  private Future<JetStreamSubscription> rebindWithSmartRetry( ConsumerDescriptor desc, long targetGen, int maxAttempts )
  {

    return attemptRebindAsync( desc, targetGen, 1, maxAttempts ).recover( err -> {
      if( maxAttempts > 1 )
      {
        // Single retry after short delay
        Promise<JetStreamSubscription> retry = Promise.promise();
        vertx.setTimer( 200, id -> {
          attemptRebindAsync( desc, targetGen, 2, maxAttempts ).onComplete( retry );
        } );
        return retry.future();
      }
      LOGGER.warn( "Failed to rebind {} after {} attempts", desc.getDurableName(), maxAttempts );
      return Future.succeededFuture( null );
    } );
  }

  /**
  * Single rebind attempt
  */
 private Future<JetStreamSubscription> attemptRebindAsync(
     ConsumerDescriptor desc, long targetGen, int attempt, int maxAttempts) {
     
     if (targetGen < currentCertificateGeneration) {
         return Future.failedFuture("Generation changed during rebind");
     }

     return bindPullConsumerAsync(
         desc.getStreamName(),
         desc.getDurableName(),
         desc.getAsyncHandler(),
         desc.getBatchSize(),
         desc.getFetchTimeoutMs(),
         desc.getPullIntervalMs(),
         desc.getExpectedFilter(),
         desc.isAutoCreate()
     );
  }

  /**
   * Stop all pull timers synchronously from blocking worker thread
   * Uses CountDownLatch to wait for event loop to cancel timers
   *
   * This is the single canonical implementation for stopping timers.
   */
  public void stopAllPullTimersSync()
  {
    Map<String, Long> timers = getAllPullTimers();
    if( timers.isEmpty() )
      return;

    final CountDownLatch latch = new CountDownLatch( timers.size() );
    final AtomicInteger stopped = new AtomicInteger( 0 );

    for( Map.Entry<String, Long> entry : timers.entrySet() )
    {
      final String key = entry.getKey();
      final Long timerId = entry.getValue();

      vertx.runOnContext( v -> {
        try
        {
          vertx.cancelTimer( timerId );
          stopped.incrementAndGet();
        }
        catch( Exception e )
        {
          LOGGER.warn( "Timer cancel failed for {}: {}", key, e.getMessage() );
        }
        finally
        {
          latch.countDown();
        }
      } );
    }

    try
    {
      boolean completed = latch.await( 2, TimeUnit.SECONDS );
      if( completed )
      {
        LOGGER.info( "✅ Stopped {} timers", stopped.get() );
      }
      else
      {
        LOGGER.warn( "Timer stop timeout - proceeding ({} stopped)", stopped.get() );
      }
    }
    catch( InterruptedException e )
    {
      Thread.currentThread().interrupt();
    }
  }

  /**
   * Attempt to rebind a consumer with retries and backoff
   */
  private void attemptRebind(ConsumerDescriptor desc, long targetGeneration, int attempt,
                            int maxAttempts, Promise<JetStreamSubscription> promise)
  {
    LOGGER.info("Rebinding pull consumer {} (attempt {}/{})", desc.getDurableName(), attempt, maxAttempts);

    // Check if generation changed during attempt
    if (targetGeneration < currentCertificateGeneration)
    {
      LOGGER.warn("Aborting rebind for {} - generation changed during attempt", desc.getDurableName());
      promise.fail("Generation changed during rebind");
      return;
    }

    bindPullConsumerAsync(
      desc.getStreamName(),
      desc.getDurableName(),
      desc.getAsyncHandler(),
      desc.getBatchSize(),
      desc.getFetchTimeoutMs(),
      desc.getPullIntervalMs(),
      desc.getExpectedFilter(),
      desc.isAutoCreate()
    ).onComplete(ar -> {
      if (ar.succeeded())
      {
        LOGGER.info("Successfully rebound pull consumer: {} (generation {})",
                   desc.getDurableName(), targetGeneration);
        promise.complete(ar.result());
      }
      else
      {
        LOGGER.warn("Rebind attempt {}/{} failed for {}: {}",
                   attempt, maxAttempts, desc.getDurableName(),
                   ar.cause() != null ? ar.cause().getMessage() : "unknown");
        handleRebindFailure(desc, targetGeneration, attempt, maxAttempts, promise, ar.cause());
      }
    });
  }

  /**
   * Handle rebind failure with exponential backoff
   */
  private void handleRebindFailure(ConsumerDescriptor desc, long targetGeneration, int attempt,
                                  int maxAttempts, Promise<JetStreamSubscription> promise, Throwable cause)
  {
    if (attempt >= maxAttempts)
    {
      LOGGER.error("Exceeded max rebind attempts ({}) for durable={}, giving up",
                  maxAttempts, desc.getDurableName());
      promise.fail(cause != null ? cause : new RuntimeException("rebind failed"));
      return;
    }

    // Exponential backoff
    long backoffMs = 200L * (1L << (attempt - 1));
    LOGGER.info("Scheduling retry {}/{} for durable={} after {}ms",
               attempt + 1, maxAttempts, desc.getDurableName(), backoffMs);

    vertx.setTimer(backoffMs, id -> attemptRebind(desc, targetGeneration, attempt + 1, maxAttempts, promise));
  }

  /**
   * Cleanup old consumers (timers already cancelled)
   * For pull consumers: just unsubscribe, no drain needed
   */
  private void cleanupOldConsumers(Map<String, ConsumerContext> oldConsumers, long oldGen)
  {
    for (Map.Entry<String, ConsumerContext> entry : oldConsumers.entrySet())
    {
      String oldKey = entry.getKey();
      ConsumerContext oldCtx = entry.getValue();
      
      if (oldCtx.generation == oldGen)
      {
        consumerPool.remove(oldKey);
        
        if (oldCtx.subscription != null)
        {
          try
          {
            oldCtx.subscription.unsubscribe();
            LOGGER.info("Cleaned up old pull consumer {} (gen {})", oldKey, oldGen);
          }
          catch (Exception e)
          {
            LOGGER.debug("Unsubscribe failed for {}: {}", oldKey, e.getMessage());
          }
        }
      }
    }
  }

  /**
   * Ensure the server-side durable exists and has the expected filter subject, or create it.
   * This helper does not mutate local client-side state.
   *
   * @param conn JetStream connection
   * @param stream Stream name
   * @param durable Durable consumer name
   * @param expectedFilter Exact expected filter subject (nullable)
   * @param autoCreate If true, create the consumer server-side when missing (idempotent)
   */
  private void ensureServerConsumer(Connection conn, String stream, String durable,
                                    String expectedFilter, boolean autoCreate) throws Exception
  {
    JetStreamManagement jsm = conn.jetStreamManagement();

    try
    {
      ConsumerInfo cinfo = jsm.getConsumerInfo(stream, durable);
      String remoteFilter = null;

      try
      {
        java.lang.reflect.Method getConfiguration = cinfo.getClass().getMethod("getConfiguration");
        if (getConfiguration != null)
        {
          Object cfg = getConfiguration.invoke(cinfo);
          if (cfg != null)
          {
            java.lang.reflect.Method getFilter = cfg.getClass().getMethod("getFilterSubject");
            Object fs = getFilter.invoke(cfg);
            if (fs != null)
              remoteFilter = fs.toString();
          }
        }
      }
      catch (NoSuchMethodException | IllegalAccessException | java.lang.reflect.InvocationTargetException reflEx)
      {
        try
        {
          java.lang.reflect.Method getConsumerConfiguration = cinfo.getClass().getMethod("getConsumerConfiguration");
          if (getConsumerConfiguration != null)
          {
            Object cfg2 = getConsumerConfiguration.invoke(cinfo);
            if (cfg2 != null)
            {
              java.lang.reflect.Method getFilter2 = cfg2.getClass().getMethod("getFilterSubject");
              Object fs2 = getFilter2.invoke(cfg2);
              if (fs2 != null)
                remoteFilter = fs2.toString();
            }
          }
        }
        catch (Exception ignored)
        {
          // cannot introspect filter subject
        }
      }

      LOGGER.debug("Server-side consumer '{}' on stream '{}' present; filterSubject='{}'",
                  durable, stream, remoteFilter);

      if (expectedFilter != null && remoteFilter != null && !expectedFilter.equals(remoteFilter))
      {
        throw new IllegalStateException(
          String.format("Consumer '%s' filter mismatch: expected='%s' got='%s'",
                       durable, expectedFilter, remoteFilter));
      }

      return;
    }
    catch (Exception e)
    {
      String msg = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
      boolean notFound = msg.contains("consumer not found") ||
                        msg.contains("stream not found") ||
                        msg.contains("10014") ||
                        msg.contains("10059");

      if (!notFound)
      {
        throw e;
      }

      if (!autoCreate)
      {
        throw new IllegalStateException("Server-side consumer not found: " + durable, e);
      }

      LOGGER.info("Server-side consumer '{}' on stream '{}' not found. Creating with filter='{}'",
                 durable, stream, expectedFilter);

      io.nats.client.api.ConsumerConfiguration cc = io.nats.client.api.ConsumerConfiguration.builder()
        .durable(durable)
        .filterSubject(expectedFilter)
        .ackPolicy(io.nats.client.api.AckPolicy.Explicit)
        .replayPolicy(io.nats.client.api.ReplayPolicy.Instant)
        .maxAckPending(1000)
        .maxDeliver(-1)
        .build();

      try
      {
        java.lang.reflect.Method addOrUpdate = null;
        try
        {
          addOrUpdate = jsm.getClass().getMethod("addOrUpdateConsumer", String.class,
                                                 io.nats.client.api.ConsumerConfiguration.class);
        }
        catch (NoSuchMethodException nsme)
        {
          addOrUpdate = null;
        }

        if (addOrUpdate != null)
        {
          addOrUpdate.invoke(jsm, stream, cc);
        }
        else
        {
          java.lang.reflect.Method addConsumer = jsm.getClass().getMethod("addConsumer", String.class,
                                                                          io.nats.client.api.ConsumerConfiguration.class);
          addConsumer.invoke(jsm, stream, cc);
        }

        LOGGER.info("Successfully created server-side consumer '{}' on stream '{}'", durable, stream);
      }
      catch (java.lang.reflect.InvocationTargetException ite)
      {
        Throwable cause = ite.getCause() != null ? ite.getCause() : ite;
        String cm = cause.getMessage() == null ? "" : cause.getMessage().toLowerCase();
        if (cm.contains("consumer already exists") || cm.contains("consumer exists"))
        {
          LOGGER.info("Consumer '{}' was concurrently created by another process - continuing", durable);
          return;
        }
        throw new RuntimeException("Failed to create server-side consumer: " + durable, cause);
      }
    }
  }

  private boolean wasProcessedButFailedToAck(String consumerKey, long streamSeq)
  {
    ConcurrentHashMap<Long, Long> seqMap = failedAckCache.get(consumerKey);
    if (seqMap == null) return false;
    
    Long timestamp = seqMap.get(streamSeq);
    if (timestamp == null) return false;
    
    // Check TTL
    long age = System.currentTimeMillis() - timestamp;
    if (age > FAILED_ACK_TTL_MS)
    {
      seqMap.remove(streamSeq);
      return false;
    }
    
    return true;
  }

  private void addToFailedAckCache(String consumerKey, long streamSeq)
  {
    failedAckCache.computeIfAbsent(consumerKey, k -> new ConcurrentHashMap<>())
                  .put(streamSeq, System.currentTimeMillis());
  }

  private void removeFromFailedAckCache(String consumerKey, long streamSeq)
  {
    ConcurrentHashMap<Long, Long> seqMap = failedAckCache.get(consumerKey);
    if (seqMap != null)
    {
      seqMap.remove(streamSeq);
    }
  }

  private void updateFailedAckCacheTimestamp(String consumerKey, long streamSeq)
  {
    ConcurrentHashMap<Long, Long> seqMap = failedAckCache.get(consumerKey);
    if (seqMap != null)
    {
      seqMap.put(streamSeq, System.currentTimeMillis());
    }
  }

  private boolean tryAck(Message msg, String key, long sequence)
  {
    try
    {
      msg.ack();
      LOGGER.debug("Message ack'd for consumer {} seq={}", key, sequence);
      return true;
    }
    catch (IllegalStateException e)
    {
      LOGGER.warn("Failed to ack message seq={} for {}: connection closed", sequence, key);
      return false;
    }
    catch (Exception e)
    {
      LOGGER.warn("Failed to ack message seq={} for {}: {}", sequence, key, e.getMessage());
      return false;
    }
  }

  private void tryNak(Message msg, String key, long sequence)
  {
    try
    {
      msg.nak();
      LOGGER.debug("Message nak'd for consumer {} seq={}", key, sequence);
    }
    catch (Exception e)
    {
      LOGGER.warn("Failed to nak message seq={} for {}: {}", sequence, key, e.getMessage());
    }
  }

  public Map<String, Object> getFailedAckCacheStats()
  {
    Map<String, Object> stats = new HashMap<>();
    
    int totalEntries = failedAckCache.values().stream()
                                     .mapToInt(Map::size)
                                     .sum();
    
    stats.put("totalFailedAcks", totalEntries);
    stats.put("consumerCount", failedAckCache.size());
    stats.put("ttlMs", FAILED_ACK_TTL_MS);
    
    Map<String, Integer> perConsumer = new HashMap<>();
    for (Map.Entry<String, ConcurrentHashMap<Long, Long>> entry : failedAckCache.entrySet())
    {
      perConsumer.put(entry.getKey(), entry.getValue().size());
    }
    stats.put("byConsumer", perConsumer);
    
    return stats;
  }


  
  /**
   * Get registered consumers
   */
  public Map<String, ConsumerDescriptor> getRegisteredConsumers()
  {
    return new HashMap<>(consumerRegistry);
  }

  /**
   * Get all active pull timers (for debugging)
   */
  public Map<String, Long> getAllPullTimers()
  {
    return new HashMap<>(pullTimers);
  }

  /**
   * Get pool health status
   */
  public Map<String, Object> getPoolHealthStatus()
  {
    Map<String, Object> health = new HashMap<>();

    health.put("currentGeneration", currentCertificateGeneration);
    health.put("activeConsumers", consumerPool.size());
    health.put("registeredConsumers", consumerRegistry.size());
    health.put("activePullTimers", pullTimers.size());

    // Count consumers by generation
    Map<Long, Integer> generationCounts = new HashMap<>();
    for (ConsumerContext ctx : consumerPool.values())
    {
      generationCounts.merge(ctx.generation, 1, Integer::sum);
    }
    health.put("consumersByGeneration", generationCounts);

    return health;
  }

  /**
   * Shutdown pool
   */
  public void shutdown()
  {
    LOGGER.info("Shutting down pull consumer pool");

    // Cancel all pull timers
    for (Map.Entry<String, Long> entry : pullTimers.entrySet())
    {
      try
      {
        vertx.cancelTimer(entry.getValue());
        LOGGER.debug("Cancelled pull timer for {}", entry.getKey());
      }
      catch (Exception e)
      {
        LOGGER.debug("Failed to cancel timer for {}: {}", entry.getKey(), e.getMessage());
      }
    }
    pullTimers.clear();

    // Unsubscribe all consumers
    for (Map.Entry<String, ConsumerContext> entry : consumerPool.entrySet())
    {
      try
      {
        if (entry.getValue().subscription != null)
        {
          entry.getValue().subscription.unsubscribe();
        }
      }
      catch (Exception e)
      {
        LOGGER.warn("Error unsubscribing consumer {}: {}", entry.getKey(), e.getMessage());
      }
    }
    consumerPool.clear();
    consumerRegistry.clear();

    LOGGER.info("Pull consumer pool shutdown complete");
  }

  public long getCurrentGeneration()
  {
    return currentCertificateGeneration;
  }
}