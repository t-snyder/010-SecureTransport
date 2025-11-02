package core.nats;

import io.nats.client.*;
import io.nats.client.api.StreamInfo;
import io.nats.client.PushSubscribeOptions;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.CertificateUpdateCallbackIF;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
//import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * NATS Consumer Pool Manager (non-blocking migration)
 *
 * - Non-blocking migration on certificate updates.
 * - Per-consumer retries/backoff when reattaching.
 * - Avoids blocking the Vert.x event loop.
 * - Tracks descriptor.createdByManager to avoid deleting admin-created durables.
 */
public class NatsConsumerPoolManager implements CertificateUpdateCallbackIF
{
  private static final Logger LOGGER = LoggerFactory.getLogger(NatsConsumerPoolManager.class);

  private final Vertx vertx;
  private final WorkerExecutor workerExecutor;
  private final NatsTLSClient natsTlsClient;

  // Generation tracking
  private final AtomicLong generationCounter = new AtomicLong(1);
  private volatile long currentCertificateGeneration = 1;

  // Track consumers being drained (old generation)
  private final ConcurrentHashMap<String, ConsumerContext> drainingConsumers = new ConcurrentHashMap<>();

  private final AtomicInteger activeDrainOperations = new AtomicInteger(0);
  private static final int    MAX_CONCURRENT_DRAINS = 10;

  // Consumer tracking
  private final ConcurrentHashMap<String, ConsumerContext>    consumerPool = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, ConsumerDescriptor> consumerRegistry = new ConcurrentHashMap<>();

  
  /**
   * Consumer context with generation, connection and dispatcher tracking
  private static class ConsumerContext
  {
    final JetStreamSubscription subscription;
    final Dispatcher dispatcher;
    final Connection connection;
    final long generation;

    ConsumerContext(JetStreamSubscription subscription, Dispatcher dispatcher, Connection connection, long generation)
    {
      this.subscription = subscription;
      this.dispatcher = dispatcher;
      this.connection = connection;
      this.generation = generation;
    }
  }
   */

  /**
   * Consumer context with generation, connection and dispatcher tracking
   * Supports either a JetStreamSubscription (server/client-managed consumer)
   * or a plain NATS Subscription (deliver subject from an admin-created server consumer).
   */
  private static class ConsumerContext
  {
    final JetStreamSubscription jsSubscription; // null when using plain NATS deliver-sub subscription
    final Subscription plainSubscription;  // null when using JetStream subscription attach
    final Dispatcher dispatcher;
    final Connection connection;
    final long generation;

    ConsumerContext(JetStreamSubscription jsSubscription, Subscription plainSubscription, Dispatcher dispatcher, Connection connection, long generation)
    {
      this.jsSubscription = jsSubscription;
      this.plainSubscription = plainSubscription;
      this.dispatcher = dispatcher;
      this.connection = connection;
      this.generation = generation;
    }

    public JetStreamSubscription getJsSubscription() { return jsSubscription; }
    public Subscription getPlainSubscription() { return plainSubscription; }

    /**
     * Returns whichever subscription is active/preferred (JetStream if present).
     */
    public Subscription getEffectiveSubscription()
    {
      return jsSubscription != null ? jsSubscription : plainSubscription;
    }

    /**
     * Safe check for "isActive" across both types.
     */
    public boolean isSubscriptionActive()
    {
      Subscription s = getEffectiveSubscription();
      if (s == null) return false;
      try {
        return s.isActive();
      } catch (Throwable t) {
        // If the client impl doesn't support .isActive() for the type, assume true to avoid premature recreation.
        return true;
      }
    }
  }
  
  public static enum ConsumerType { PUSH_QUEUE, PULL_DURABLE }

  /**
   * Consumer descriptor for recreation
   *
   * createdByManager: true => manager-created server-side durable (safe to delete)
   *                  false => admin-created durable (do not delete server-side)
   */
  public static class ConsumerDescriptor
  {
    private final String         subject;
    private final String         consumerNameOrQueue; // durable name or queue group
    private final MessageHandler handler;
    private final ConsumerType   type;
    private final boolean        createdByManager;

    public ConsumerDescriptor(String subject, String consumerNameOrQueue, MessageHandler handler, ConsumerType type, boolean createdByManager) {
      this.subject             = subject;
      this.consumerNameOrQueue = consumerNameOrQueue;
      this.handler             = handler;
      this.type                = type;
      this.createdByManager    = createdByManager;
    }

    public String         getSubject()             { return subject;             }
    public String         getConsumerNameOrQueue() { return consumerNameOrQueue; }
    public MessageHandler getHandler()             { return handler;             }
    public ConsumerType   getType()                { return type;                }
    public boolean        isCreatedByManager()     { return createdByManager;    }
  }

  public NatsConsumerPoolManager(Vertx vertx, NatsTLSClient natsTlsClient)
  {
    this.vertx = vertx;
    // create a small worker executor for blocking flush/drain work (adjust size if needed)
    this.workerExecutor = vertx.createSharedWorkerExecutor("nats-consumer-cleanup", 2);
    this.natsTlsClient = natsTlsClient;
  }

  /**
   * Attach to an existing server-side push/queue consumer by subscribing to the
   * deliver subject with the queue group. This assumes the admin created a push
   * consumer with deliverSubject and deliverGroup (queue).
   *
   * NOTE: register descriptor with createdByManager = false (admin-owned).
   *
   * Behavior change:
   * - If the descriptor is admin-created (createdByManager == false), subscribe
   *   directly to the deliver subject (plain NATS subscription with queue group).
   *   This consumes the server-managed push consumer delivery target and avoids
   *   creating a new JetStream consumer on the server (which caused replays).
   * - Otherwise fall back to client-managed JetStream subscribe (same as before).
   */
  public Future<Subscription> attachPushQueue( String deliverSubject, String queueGroup, MessageHandler handler )
  {
    return vertx.executeBlocking( () -> 
    {
      String key = deliverSubject + ":queue:" + queueGroup;
      long currentGen = currentCertificateGeneration;

      // Register descriptor as admin-owned by default (upstream logic may
      // override)
      consumerRegistry.putIfAbsent( key, new ConsumerDescriptor( deliverSubject, queueGroup, handler, ConsumerType.PUSH_QUEUE, false ) );

      ConsumerContext ctx = consumerPool.get( key );
      if( ctx != null && ctx.generation == currentGen )
      {
        try
        {
          if( ctx.isSubscriptionActive() )
          {
            Connection conn = ctx.connection;
            if( conn != null && conn.getStatus() == Connection.Status.CONNECTED )
            {
              LOGGER.debug( "Reusing push-queue subscription: {} (generation {})", key, currentGen );
              return (Subscription)ctx.getEffectiveSubscription();
            }
          }
        }
        catch( Exception e )
        {
          LOGGER.info( "Validation failed for existing push-queue subscription {}, recreating: {}", key, e.getMessage(), e );
        }
      }

      if( ctx != null )
      {
        cleanupConsumerContext( key, ctx );
        consumerPool.remove( key );
      }

      Connection conn = natsTlsClient.getConnectionForNewOperations();
      if( conn == null || conn.getStatus() != Connection.Status.CONNECTED )
      {
        throw new IllegalStateException( "No NATS connection available for push queue subscribe" );
      }

      Dispatcher dispatcher = conn.createDispatcher();
      LOGGER.info( "Subscribing to push-queue: subject={} queue={} (gen={})", deliverSubject, queueGroup, currentGen );

      // Inspect registry entry to see if this consumer was admin-created.
      ConsumerDescriptor desc = consumerRegistry.get( key );

      // If descriptor exists and is admin-created, subscribe to the deliver
      // subject directly (plain NATS subscription).
      if( desc != null && !desc.isCreatedByManager() )
      {
        LOGGER.info( "Detected admin-created consumer for key {} - subscribing to deliver subject directly", key );
        // Subscribe to the deliver subject with queue semantics (server will
        // deliver to this deliver subject)
        Subscription plainSub;
        try
        {
          if( queueGroup == null || queueGroup.isBlank() )
          {
            // subscribe without queue group (each client receives its own
            // deliveries to this deliver subject)
            plainSub = dispatcher.subscribe( deliverSubject, desc.getHandler() );
          }
          else
          {
            // subscribe with queue group (legacy behavior, load-balanced)
            plainSub = dispatcher.subscribe( deliverSubject, queueGroup, desc.getHandler() );
          }
        }
        catch( Exception e )
        {
          LOGGER.warn( "Failed to subscribe to deliver subject {} as plain subscription: {}. Falling back to JetStream subscribe", deliverSubject, e.getMessage() );
          plainSub = null;
        }
        if( plainSub != null )
        {
          ConsumerContext newCtx = new ConsumerContext( null, plainSub, dispatcher, conn, currentGen );
          consumerPool.put( key, newCtx );
          LOGGER.info( "Attached plain deliver-subscription: {} (generation {})", key, currentGen );
          return (Subscription)plainSub;
        }
        // else fallthrough to JetStream binding
      }

      // Fallback / client-managed JetStream subscription
      // If the server consumer exists and a durable name is known (e.g.,
      // consumerRegistry stored it),
      // you could set .durable(durableName) here to bind. For now, mirror
      // previous behavior but prefer
      // to bind to durable when descriptor indicates manager-created consumer
      // (if available).
      PushSubscribeOptions pushOpts = PushSubscribeOptions.builder().deliverGroup( queueGroup ).build();

      JetStreamSubscription jss = conn.jetStream().subscribe( deliverSubject, dispatcher, handler, false, pushOpts );

      ConsumerContext newCtx = new ConsumerContext( jss, null, dispatcher, conn, currentGen );
      consumerPool.put( key, newCtx );

      LOGGER.info( "Attached push-queue subscription: {} (generation {})", key, currentGen );
      return (Subscription)jss;
    } );
  }

  /**
   * Attach/bind to an existing server-side pull durable consumer by durable name.
   * This binds the client subscription to the server durable (no admin create attempted).
   *
   * NOTE: register descriptor with createdByManager = false (admin-owned).
   *
   * NOTE: This code path uses push-style handler attach as a fallback for
   * environments that only use push deliveries. If you need true pull-mode,
   * implement a dedicated pull-mode attach + fetch loop.
   *
   * Behavior change:
   * - If runtime cannot create a true pull subscription and must fall back to a push
   *   subscriber, attempt to bind to the existing durable by specifying durable(durableName).
   *   That avoids creation of a new ephemeral consumer on the server.
   */
  public Future<Subscription> attachPullConsumer(String subject, String durableName, MessageHandler handler) {
    return vertx.executeBlocking(() -> {
      String key = subject + ":" + durableName;
      long currentGen = currentCertificateGeneration;

      // Register descriptor as admin-owned (we did NOT create the server durable)
      consumerRegistry.putIfAbsent(key, new ConsumerDescriptor(subject, durableName, handler, ConsumerType.PULL_DURABLE, false));

      ConsumerContext ctx = consumerPool.get(key);
      if (ctx != null && ctx.generation == currentGen) {
        try {
          if (ctx.isSubscriptionActive()) {
            Connection conn = ctx.connection;
            if (conn != null && conn.getStatus() == Connection.Status.CONNECTED) {
              LOGGER.debug("Reusing pull-bound subscription: {} (generation {})", key, currentGen);
              return (Subscription) ctx.getEffectiveSubscription();
            }
          }
        } catch (Exception e) {
          LOGGER.info("Validation failed for existing pull-bound subscription {}, recreating: {}", key, e.getMessage());
        }
      }

      if (ctx != null) {
        cleanupConsumerContext(key, ctx);
        consumerPool.remove(key);
      }

      Connection conn = natsTlsClient.getConnectionForNewOperations();
      if (conn == null || conn.getStatus() != Connection.Status.CONNECTED) {
        throw new IllegalStateException("No NATS connection available for pull bind");
      }

      LOGGER.info("Binding to pull-durable fallback (push subscribe) subject={} durable={} (gen={})", subject, durableName, currentGen);

      Dispatcher dispatcher = conn.createDispatcher();

      // Attempt to bind to existing durable on server by specifying durable name in PushSubscribeOptions.
      // This avoids creating a new ephemeral consumer object on the server.
      JetStreamSubscription jss;
      try {
        PushSubscribeOptions bindOpts = PushSubscribeOptions.builder()
          .durable(durableName)
          .build();

        jss = conn.jetStream().subscribe(subject, dispatcher, handler, false, bindOpts);
      } catch (Exception e) {
        LOGGER.warn("Binding to durable {} failed (falling back to non-durable push subscribe): {}", durableName, e.getMessage());
        jss = conn.jetStream().subscribe(subject, dispatcher, handler, false);
      }

      ConsumerContext newCtx = new ConsumerContext(jss, null, dispatcher, conn, currentGen);
      consumerPool.put(key, newCtx);

      LOGGER.info("Attached (push-fallback) subscription for key={} (generation {})", key, currentGen);
      return (Subscription) jss;
    });
  }  
  
  
  /**
   * Attach to an existing server-side push/queue consumer by subscribing to the
   * deliver subject with the queue group. This assumes the admin created a push
   * consumer with deliverSubject and deliverGroup (queue).
   *
   * NOTE: register descriptor with createdByManager = false (admin-owned).
  public Future<Subscription> attachPushQueue( String deliverSubject, String queueGroup, MessageHandler handler )
  {
    return vertx.executeBlocking(() ->
    {
      String key = deliverSubject + ":queue:" + queueGroup;
      long currentGen = currentCertificateGeneration;

      // Register descriptor as admin-owned
      consumerRegistry.putIfAbsent(key,
        new ConsumerDescriptor(deliverSubject, queueGroup, handler, ConsumerType.PUSH_QUEUE, false));

      ConsumerContext ctx = consumerPool.get(key);
      if (ctx != null && ctx.generation == currentGen) {
        if (ctx.subscription != null && ctx.subscription.isActive()) {
          try {
            Connection conn = ctx.connection;
            if (conn != null && conn.getStatus() == Connection.Status.CONNECTED) {
              LOGGER.debug("Reusing push-queue subscription: {} (generation {})", key, currentGen);
              return (Subscription) ctx.subscription;
            }
          } catch (Exception e) {
            LOGGER.info("Validation failed for existing push-queue subscription {}, recreating: {}", key, e.getMessage(), e);
          }
        }
      }

      if (ctx != null) {
        cleanupConsumerContext(key, ctx);
        consumerPool.remove(key);
      }

      Connection conn = natsTlsClient.getConnectionForNewOperations();
      if (conn == null || conn.getStatus() != Connection.Status.CONNECTED) {
        throw new IllegalStateException("No NATS connection available for push queue subscribe");
      }

      Dispatcher dispatcher = conn.createDispatcher();
      LOGGER.info("Subscribing to push-queue: subject={} queue={} (gen={})", deliverSubject, queueGroup, currentGen);

      // Build PushSubscribeOptions with deliverGroup
      PushSubscribeOptions pushOpts = PushSubscribeOptions.builder()
        .deliverGroup(queueGroup)
        .build();

      // Use dispatcher-first overload: subscribe(subject, dispatcher, handler, autoAck, pushOpts)
      JetStreamSubscription jss = conn.jetStream().subscribe(deliverSubject, dispatcher, handler, false, pushOpts);

      ConsumerContext newCtx = new ConsumerContext(jss, dispatcher, conn, currentGen);
      consumerPool.put(key, newCtx);

      LOGGER.info("Attached push-queue subscription: {} (generation {})", key, currentGen);
      return (Subscription) jss;
    });
  }
   */

  /**
   * Attach/bind to an existing server-side pull durable consumer by durable name.
   * This binds the client subscription to the server durable (no admin create attempted).
   *
   * NOTE: register descriptor with createdByManager = false (admin-owned).
   *
   * NOTE: This code path uses push-style handler attach as a fallback for
   * environments that only use push deliveries. If you need true pull-mode,
   * implement a dedicated pull-mode attach + fetch loop.
  public Future<Subscription> attachPullConsumer(String subject, String durableName, MessageHandler handler) {
    return vertx.executeBlocking(() -> {
      String key = subject + ":" + durableName;
      long currentGen = currentCertificateGeneration;

      // Register descriptor as admin-owned (we did NOT create the server durable)
      consumerRegistry.putIfAbsent(key, new ConsumerDescriptor(subject, durableName, handler, ConsumerType.PULL_DURABLE, false));

      ConsumerContext ctx = consumerPool.get(key);
      if (ctx != null && ctx.generation == currentGen) {
        if (ctx.subscription != null && ctx.subscription.isActive()) {
          try {
            Connection conn = ctx.connection;
            if (conn != null && conn.getStatus() == Connection.Status.CONNECTED) {
              LOGGER.debug("Reusing pull-bound subscription: {} (generation {})", key, currentGen);
              return (Subscription) ctx.subscription;
            }
          } catch (Exception e) {
            LOGGER.info("Validation failed for existing pull-bound subscription {}, recreating: {}", key, e.getMessage());
          }
        }
      }

      if (ctx != null) {
        cleanupConsumerContext(key, ctx);
        consumerPool.remove(key);
      }

      Connection conn = natsTlsClient.getConnectionForNewOperations();
      if (conn == null || conn.getStatus() != Connection.Status.CONNECTED) {
        throw new IllegalStateException("No NATS connection available for pull bind");
      }

      LOGGER.info("Binding to pull-durable fallback (push subscribe) subject={} durable={} (gen={})", subject, durableName, currentGen);

      // Fallback: your runtime uses push-mode only. Create a push-style subscription
      // that attaches to the subject and delivers to the provided handler.
      Dispatcher dispatcher = conn.createDispatcher();
      JetStreamSubscription jss = conn.jetStream().subscribe(subject, dispatcher, handler, false);

      ConsumerContext newCtx = new ConsumerContext(jss, dispatcher, conn, currentGen);
      consumerPool.put(key, newCtx);

      LOGGER.info("Attached (push-fallback) subscription for key={} (generation {})", key, currentGen);
      return (Subscription) jss;
    });
  }
   */

  /**
   * Helper: cleanup consumer context asynchronously (delegates to blocking method).
   */
  private void cleanupConsumerContext(String key, ConsumerContext ctx)
  {
    if (ctx == null) return;

    try
    {
      workerExecutor.executeBlocking(() -> {
        cleanupConsumerContextBlocking(key, ctx);
        return null;
      }).onComplete(ar -> {
        if (ar.failed()) {
          LOGGER.warn("Async cleanup failed for {}: {}", key, ar.cause() != null ? ar.cause().getMessage() : "unknown");
        } else {
          LOGGER.debug("Async cleanup completed for {}", key);
        }
      });
    }
    catch (Exception e)
    {
      LOGGER.warn("Failed to offload consumer cleanup to worker for {}: {}. Doing inline cleanup.", key, e.getMessage());
      cleanupConsumerContextBlocking(key, ctx);
    }
  }

  /**
   * Properly cleanup a ConsumerContext (blocking).
   *
   * Updated to support both JetStreamSubscription and plain Subscription.
   */
  private void cleanupConsumerContextBlocking(String key, ConsumerContext ctx)
  {
    if (ctx == null) return;

    LOGGER.info("Cleaning up consumer context: {}", key);

    JetStreamSubscription jss = ctx.getJsSubscription();
    Subscription plainSub = ctx.getPlainSubscription();

    // If this is a JetStream subscription, prefer graceful drain then unsubscribe
    if (jss != null) {
      boolean drained = false;
      try {
        try {
          jss.drain(Duration.ofMillis(200));
          drained = true;
        } catch (Throwable t) {
          // fallback to unsubscribe
          LOGGER.debug("Quick drain not available/failed for {}: {}", key, t.getMessage());
        }

        if (!drained) {
          try { jss.unsubscribe(); } catch (Exception ignore) {}
        } else {
          try { jss.unsubscribe(); } catch (Exception ignore) {}
        }
      } catch (Throwable t) {
        LOGGER.debug("Error during JetStream subscription cleanup for {}: {}", key, t.getMessage(), t);
      }
    } else if (plainSub != null) {
      // Plain NATS subscription - just unsubscribe
      try {
        plainSub.unsubscribe();
      } catch (Throwable t) {
        LOGGER.debug("Unsubscribe failed for plain subscription {}: {}", key, t.getMessage());
      }
    }

    LOGGER.debug("Dropped dispatcher reference for {}", key);
  }
  
  /**
   * Properly cleanup a ConsumerContext (blocking).
  private void cleanupConsumerContextBlocking(String key, ConsumerContext ctx)
  {
    if (ctx == null) return;

    LOGGER.info("Cleaning up consumer context: {}", key);

    JetStreamSubscription jss = ctx.subscription;
    if (jss != null) {
      boolean drained = false;
      try {
        // Try drain(duration) if available, else unsubscribe
        try {
          jss.drain(Duration.ofMillis(200));
          drained = true;
        } catch (Throwable t) {
          // fallback to unsubscribe
          LOGGER.debug("Quick drain not available/failed for {}: {}", key, t.getMessage());
        }

        if (!drained) {
          try { jss.unsubscribe(); } catch (Exception ignore) {}
        } else {
          try { jss.unsubscribe(); } catch (Exception ignore) {}
        }
      } catch (Throwable t) {
        LOGGER.debug("Error during subscription cleanup for {}: {}", key, t.getMessage(), t);
      }
    }

    LOGGER.debug("Dropped dispatcher reference for {}", key);
  }
   */

  /**
   * Implement CertificateUpdateCallbackIF: handle certificate update event
   * by bumping generation and migrating consumers.
   *
   * Non-blocking: schedule migration on workerExecutor so event-loop is never blocked.
   */
  @Override
  public void onCertificateUpdated()
  {
    long oldGeneration = currentCertificateGeneration;
    long newGeneration = generationCounter.incrementAndGet();
    
    // CRITICAL: Update currentCertificateGeneration BEFORE starting migration
    currentCertificateGeneration = newGeneration;

    LOGGER.info("Consumer pool: Certificate updated - old gen: {}, new gen: {}", 
      oldGeneration, newGeneration);

    // FIXED: Don't wrap migration in executeBlocking - let it manage its own threading
    // The async migration already handles worker thread coordination
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

  /**
   * Asynchronous, non-blocking migration that attempts to reattach to admin-managed
   * consumers on the new connection. Per-consumer retries/backoff tolerates transient races.
   */
  private Future<Void> migrateConsumersToNewGenerationAsync(long oldGen, long newGen)
  {
    Promise<Void> overall = Promise.promise();
    
    // Set overall timeout for migration
    long timeoutId = vertx.setTimer(90000, id -> {
      if (!overall.future().isComplete())
      {
        LOGGER.error("Consumer migration timed out after 90 seconds");
        overall.fail("Migration timeout");
      }
    });

    Map<String, ConsumerDescriptor> descriptors = new HashMap<>(consumerRegistry);
    Map<String, ConsumerContext> oldConsumers = new HashMap<>(consumerPool);

    LOGGER.info("Migrating consumers: gen {} → gen {} ({} descriptors)", 
      oldGen, newGen, descriptors.size());

    if (descriptors.isEmpty())
    {
      drainOldConsumers(oldConsumers, oldGen);
      vertx.cancelTimer(timeoutId);
      overall.complete();
      return overall.future();
    }

    List<String> descriptorKeys = new ArrayList<>(descriptors.keySet());
    List<Future<ConsumerContext>> safeFutures = new ArrayList<>(descriptorKeys.size());

    for (String regKey : descriptorKeys)
    {
      ConsumerDescriptor desc = descriptors.get(regKey);

      Promise<ConsumerContext> attachPromise = Promise.promise();
      
      // FIXED: Add timeout per consumer attempt
      long consumerTimeoutId = vertx.setTimer(30000, id -> {
        if (!attachPromise.future().isComplete())
        {
          LOGGER.warn("Reattach timeout for {}", desc.getSubject());
          attachPromise.fail("Consumer reattach timeout");
        }
      });
      
      attemptReattach(desc, newGen, 1, 3, attachPromise);
      
      // Cancel timeout on completion
      attachPromise.future().onComplete(ar -> vertx.cancelTimer(consumerTimeoutId));

      Future<ConsumerContext> safe = attachPromise.future().recover(err -> {
        LOGGER.debug("Reattach failed for {}: {}", desc.getSubject(), 
          err == null ? "null" : err.getMessage());
        return Future.succeededFuture((ConsumerContext) null);
      });

      safeFutures.add(safe);
    }

    // Aggregate all consumer reattach attempts
    final int total = safeFutures.size();
    final AtomicInteger remaining = new AtomicInteger(total);
    final Map<Integer, ConsumerContext> resultsByIndex = new ConcurrentHashMap<>();

    for (int i = 0; i < safeFutures.size(); i++)
    {
      final int idx = i;
      Future<ConsumerContext> f = safeFutures.get(i);
      
      f.onComplete(ar -> {
        if (ar.succeeded())
        {
          resultsByIndex.put(idx, ar.result());
        }
        else
        {
          resultsByIndex.put(idx, null);
        }

        if (remaining.decrementAndGet() == 0)
        {
          // All completed - process results
          Map<String, ConsumerContext> created = new HashMap<>();
          int successCount = 0;
          int failCount = 0;
          
          for (int j = 0; j < descriptorKeys.size(); j++)
          {
            String regKey = descriptorKeys.get(j);
            ConsumerContext ctx = resultsByIndex.get(j);
            
            if (ctx != null)
            {
              created.put(regKey, ctx);
              successCount++;
              LOGGER.info("Reattached consumer registryKey={} (gen {})", regKey, newGen);
            }
            else
            {
              failCount++;
              LOGGER.warn("Failed to reattach consumer registryKey={}", regKey);
            }
          }

          // Activate newly created contexts
          for (Map.Entry<String, ConsumerContext> e : created.entrySet())
          {
            consumerPool.put(e.getKey(), e.getValue());
          }
          
          LOGGER.info("Activated {} consumers (success: {}, failed: {})", 
            created.size(), successCount, failCount);

          // Drain old-generation contexts
          drainOldConsumers(oldConsumers, oldGen);

          vertx.cancelTimer(timeoutId);
          
          if (failCount > 0)
          {
            overall.fail("Failed to reattach " + failCount + " consumers");
          }
          else
          {
            overall.complete();
          }
        }
      });
    }

    return overall.future();
  }
 
  /**
   * Attempt to reattach a descriptor with retries and exponential backoff.
   * - attempts: current attempt number (1-based)
   * - maxAttempts: maximum attempts
   *
   * NOTE: on successful attach, the code now builds ConsumerContext that holds
   * either a JetStreamSubscription or a plain Subscription depending on the returned type.
   */
  private void attemptReattach( ConsumerDescriptor desc, long targetGeneration, int attempt, int maxAttempts, Promise<ConsumerContext> promise )
  {
    LOGGER.info( "Reattaching {} (attempt {}/{})", desc.getSubject(), attempt, maxAttempts );

    // Check if we should abort due to generation change
    if( targetGeneration < currentCertificateGeneration )
    {
      LOGGER.warn( "Aborting reattach for {} - generation changed during attempt", desc.getSubject() );
      promise.fail( "Generation changed during reattach" );
      return;
    }

    Future<Subscription> attachFuture;
    try
    {
      if( desc.getType() == ConsumerType.PUSH_QUEUE )
      {
        attachFuture = attachPushQueue( desc.getSubject(), desc.getConsumerNameOrQueue(), desc.getHandler() );
      }
      else
      {
        attachFuture = attachPullConsumer( desc.getSubject(), desc.getConsumerNameOrQueue(), desc.getHandler() );
      }
    }
    catch( Exception e )
    {
      LOGGER.warn( "Exception creating reattach future: {}", e.getMessage(), e );
      handleReattachFailure( desc, targetGeneration, attempt, maxAttempts, promise, e );
      return;
    }

    attachFuture.onComplete( ar -> {
      if( ar.succeeded() )
      {
        try
        {
          Subscription sub = ar.result();
          Connection conn = natsTlsClient.getConnectionForNewOperations();

          if( conn == null )
          {
            throw new IllegalStateException( "No connection available after reattach" );
          }

          Dispatcher dispatcher = conn.createDispatcher();

          JetStreamSubscription jss = null;
          if (sub instanceof JetStreamSubscription) {
            jss = (JetStreamSubscription) sub;
          }

          ConsumerContext ctx = new ConsumerContext(jss, sub, dispatcher, conn, targetGeneration);

          promise.complete( ctx );
        }
        catch( Exception e )
        {
          LOGGER.warn( "Failed to build context after successful attach: {}", e.getMessage(), e );
          handleReattachFailure( desc, targetGeneration, attempt, maxAttempts, promise, e );
        }
      }
      else
      {
        LOGGER.warn( "Reattach attempt {}/{} failed for {}: {}", attempt, maxAttempts, desc.getSubject(), ar.cause() != null ? ar.cause().getMessage() : "unknown" );
        handleReattachFailure( desc, targetGeneration, attempt, maxAttempts, promise, ar.cause() );
      }
    } );
  }

  /**
   * Attempt to reattach a descriptor with retries and exponential backoff.
   * - attempts: current attempt number (1-based)
   * - maxAttempts: maximum attempts
  private void attemptReattach( ConsumerDescriptor desc, long targetGeneration, int attempt, int maxAttempts, Promise<ConsumerContext> promise )
  {
    LOGGER.info( "Reattaching {} (attempt {}/{})", desc.getSubject(), attempt, maxAttempts );

    // Check if we should abort due to generation change
    if( targetGeneration < currentCertificateGeneration )
    {
      LOGGER.warn( "Aborting reattach for {} - generation changed during attempt", desc.getSubject() );
      promise.fail( "Generation changed during reattach" );
      return;
    }

    Future<Subscription> attachFuture;
    try
    {
      if( desc.getType() == ConsumerType.PUSH_QUEUE )
      {
        attachFuture = attachPushQueue( desc.getSubject(), desc.getConsumerNameOrQueue(), desc.getHandler() );
      }
      else
      {
        attachFuture = attachPullConsumer( desc.getSubject(), desc.getConsumerNameOrQueue(), desc.getHandler() );
      }
    }
    catch( Exception e )
    {
      LOGGER.warn( "Exception creating reattach future: {}", e.getMessage(), e );
      handleReattachFailure( desc, targetGeneration, attempt, maxAttempts, promise, e );
      return;
    }

    attachFuture.onComplete( ar -> {
      if( ar.succeeded() )
      {
        try
        {
          Subscription sub = ar.result();
          Connection conn = natsTlsClient.getConnectionForNewOperations();

          if( conn == null )
          {
            throw new IllegalStateException( "No connection available after reattach" );
          }

          Dispatcher dispatcher = conn.createDispatcher();
          ConsumerContext ctx = new ConsumerContext( (JetStreamSubscription)sub, dispatcher, conn, targetGeneration );

          promise.complete( ctx );
        }
        catch( Exception e )
        {
          LOGGER.warn( "Failed to build context after successful attach: {}", e.getMessage(), e );
          handleReattachFailure( desc, targetGeneration, attempt, maxAttempts, promise, e );
        }
      }
      else
      {
        LOGGER.warn( "Reattach attempt {}/{} failed for {}: {}", attempt, maxAttempts, desc.getSubject(), ar.cause() != null ? ar.cause().getMessage() : "unknown" );
        handleReattachFailure( desc, targetGeneration, attempt, maxAttempts, promise, ar.cause() );
      }
    } );
  }
   */
  
  private void handleReattachFailure( ConsumerDescriptor desc, long targetGeneration, int attempt, int maxAttempts, Promise<ConsumerContext> promise, Throwable cause )
  {
    if( attempt >= maxAttempts )
    {
      LOGGER.error( "Exceeded max reattach attempts ({}) for subject={}, giving up", maxAttempts, desc.getSubject() );
      promise.fail( cause != null ? cause : new RuntimeException( "reattach failed" ) );
      return;
    }

    // Exponential backoff (ms): 200, 400, 800, ...
    long backoffMs = 200L * ( 1L << ( attempt - 1 ) );
    LOGGER.info( "Scheduling retry {}/{} for subject={} after {}ms", attempt + 1, maxAttempts, desc.getSubject(), backoffMs );

    vertx.setTimer( backoffMs, id -> attemptReattach( desc, targetGeneration, attempt + 1, maxAttempts, promise ) );
  }

  /**
   * Drain/unsubscribe old-generation contexts (non-blocking scheduling)
   */
  private void drainOldConsumers( Map<String, ConsumerContext> oldConsumers, long oldGen )
  {
    for( Map.Entry<String, ConsumerContext> entry : oldConsumers.entrySet() )
    {
      String oldKey = entry.getKey();
      ConsumerContext oldCtx = entry.getValue();
      if( oldCtx.generation == oldGen )
      {
        LOGGER.info( "Draining old consumer: {} (gen {})", oldKey, oldGen );
        drainingConsumers.put( oldKey, oldCtx );
        consumerPool.remove( oldKey );
        drainConsumerAsync( oldKey, oldCtx );
      }
    }
  }
  
  /**
   * Drain consumer asynchronously and clean up both client and server resources when complete
   private void drainConsumerAsync(String key, ConsumerContext ctx)
  {
    if (ctx == null || ctx.subscription == null)
    {
      drainingConsumers.remove(key);
      return;
    }

    LOGGER.info("Starting async drain for consumer: {} (gen {})", key, ctx.generation);

    workerExecutor.executeBlocking(() ->
    {
      JetStreamSubscription jss = ctx.subscription;
      String consumerName = extractConsumerName(key);
      String subject = extractSubject(key);

      try
      {
        try
        {
          jss.drain(Duration.ofSeconds(10));
          LOGGER.info("Drain initiated for consumer: {}", key);

          Thread.sleep(500);

          int attempts = 0;
          while (jss.isActive() && attempts < 20)
          {
            Thread.sleep(500);
            attempts++;
          }

          if (jss.isActive())
          {
            LOGGER.warn("Drain timeout for consumer: {}, forcing unsubscribe", key);
            jss.unsubscribe();
          }
          else
          {
            LOGGER.info("✅ Drain completed for consumer: {}", key);
          }
        }
        catch (Exception drainEx)
        {
          LOGGER.warn("Drain failed for consumer: {}, forcing unsubscribe: {}", key, drainEx.getMessage());
          try { jss.unsubscribe(); } catch (Exception unsubEx) {}
        }

        // Step 2: Clean up server-side consumer (only if manager created it)
        deleteServerSideConsumer(ctx.connection, subject, consumerName);

        return null;
      }
      catch (Exception e)
      {
        LOGGER.error("Error during async drain for consumer: {}", key, e);
        return null;
      }
    }).onComplete(ar ->
    {
      drainingConsumers.remove(key);
      consumerRegistry.remove(key);

      if (ar.succeeded())
      {
        LOGGER.info("✅ Completed full cleanup (client + server) for old consumer: {}", key);
      }
      else
      {
        LOGGER.warn("Cleanup completed with errors for consumer: {}", key);
      }
    });
  }
  */

  /**
   * Drain consumer asynchronously and clean up both client and server resources when complete
   *
   * Updated to support both JetStreamSubscription and plain Subscription.
   */
  private void drainConsumerAsync(String key, ConsumerContext ctx)
  {
    if (ctx == null || ctx.getEffectiveSubscription() == null)
    {
      drainingConsumers.remove(key);
      return;
    }

    // FIXED: Limit concurrent drain operations to prevent thread pool exhaustion
    int drainCount = activeDrainOperations.incrementAndGet();
    if (drainCount > MAX_CONCURRENT_DRAINS)
    {
      LOGGER.warn("Too many concurrent drain operations ({}), deferring drain of {}", 
        drainCount, key);
      
      activeDrainOperations.decrementAndGet();
      
      // Schedule for later (5 seconds)
      vertx.setTimer(5000, id -> drainConsumerAsync(key, ctx));
      return;
    }

    LOGGER.info("Starting async drain for consumer: {} (gen {}) [active drains: {}]", 
      key, ctx.generation, drainCount);

    workerExecutor.executeBlocking(() -> {
      JetStreamSubscription jss = ctx.getJsSubscription();
      Subscription plainSub = ctx.getPlainSubscription();
      String consumerName = extractConsumerName(key);
      String subject = extractSubject(key);

      try
      {
        if (jss != null)
        {
          // JetStream subscription: attempt graceful drain
          try
          {
            jss.drain(Duration.ofSeconds(5)); // Reduced timeout from 10 to 5
            LOGGER.info("Drain initiated for consumer: {}", key);
          }
          catch (IllegalStateException ise)
          {
            LOGGER.debug("Drain not possible for {}: {}", key, ise.getMessage());
          }
          catch (Throwable drainEx)
          {
            LOGGER.warn("Drain failed for {}: {}", key, drainEx.getMessage());
          }

          // Wait for drain to complete with timeout
          try
          {
            int attempts = 0;
            while (jss.isActive() && attempts < 10) // Reduced from 20 to 10
            {
              Thread.sleep(250);
              attempts++;
            }
            
            if (jss.isActive())
            {
              LOGGER.warn("Drain timeout for {}, forcing unsubscribe", key);
              try 
              { 
                jss.unsubscribe(); 
              } 
              catch (Throwable unsubEx) 
              {
                LOGGER.debug("Unsubscribe after timeout failed for {}", key);
              }
            }
            else
            {
              LOGGER.info("✅ Drain completed for consumer: {}", key);
            }
          }
          catch (InterruptedException ie)
          {
            Thread.currentThread().interrupt();
            LOGGER.debug("Interrupted while draining {}", key);
          }
        }
        else if (plainSub != null)
        {
          // Plain NATS subscription: unsubscribe directly (no drain)
          try
          {
            plainSub.unsubscribe();
            LOGGER.info("Unsubscribed plain deliver-subscription for {}", key);
          }
          catch (Throwable unsubEx)
          {
            LOGGER.debug("Unsubscribe for plain subscription {} failed: {}", key, unsubEx.getMessage());
          }
        }
        else
        {
          LOGGER.debug("No subscription present for {} - skipping drain", key);
        }

        // Server-side cleanup (only if manager-created and connection active)
        try
        {
          if (ctx.connection != null && 
              ctx.connection.getStatus() == Connection.Status.CONNECTED)
          {
            deleteServerSideConsumer(ctx.connection, subject, consumerName);
          }
          else
          {
            LOGGER.debug("Skipping server-side deletion for {} (connection not active)", key);
          }
        }
        catch (Throwable t)
        {
          LOGGER.warn("Server-side deletion failed for {}: {}", key, t.getMessage());
        }
      }
      catch (Throwable e)
      {
        LOGGER.warn("Error during drain for {}: {}", key, e.getMessage());
        // Final cleanup attempt
        try 
        { 
          if (ctx.getEffectiveSubscription() != null) ctx.getEffectiveSubscription().unsubscribe(); 
        } 
        catch (Throwable ignore) 
        {
          LOGGER.debug("Final unsubscribe failed for {}", key);
        }
      }

      return null;
    }).onComplete(ar -> {
      // Always decrement counter and remove from draining map
      activeDrainOperations.decrementAndGet();
      drainingConsumers.remove(key);

      // Only remove registry entry if manager created the consumer
      try
      {
        ConsumerDescriptor desc = consumerRegistry.get(key);
        if (desc != null && desc.isCreatedByManager())
        {
          consumerRegistry.remove(key);
          LOGGER.debug("Removed manager-created consumer registry entry for {}", key);
        }
        else
        {
          LOGGER.debug("Preserving registry entry for {} (admin-owned or missing)", key);
        }
      }
      catch (Throwable t)
      {
        LOGGER.warn("Error updating registry for {}: {}", key, t.getMessage());
      }

      if (ar.succeeded())
      {
        LOGGER.info("✅ Completed cleanup for: {}", key);
      }
      else
      {
        LOGGER.warn("Cleanup completed with errors for: {} - {}", key, 
          ar.cause() != null ? ar.cause().getMessage() : "unknown");
      }
    });
  }
  
/**  
  private void drainConsumerAsync(String key, ConsumerContext ctx)
  {
    if (ctx == null || ctx.subscription == null)
    {
      drainingConsumers.remove(key);
      return;
    }

    // FIXED: Limit concurrent drain operations to prevent thread pool exhaustion
    int drainCount = activeDrainOperations.incrementAndGet();
    if (drainCount > MAX_CONCURRENT_DRAINS)
    {
      LOGGER.warn("Too many concurrent drain operations ({}), deferring drain of {}", 
        drainCount, key);
      
      activeDrainOperations.decrementAndGet();
      
      // Schedule for later (5 seconds)
      vertx.setTimer(5000, id -> drainConsumerAsync(key, ctx));
      return;
    }

    LOGGER.info("Starting async drain for consumer: {} (gen {}) [active drains: {}]", 
      key, ctx.generation, drainCount);

    workerExecutor.executeBlocking(() -> {
      JetStreamSubscription jss = ctx.subscription;
      String consumerName = extractConsumerName(key);
      String subject = extractSubject(key);

      try
      {
        // Check if subscription is still active
        boolean isActive = false;
        try
        {
          isActive = jss.isActive();
        }
        catch (Throwable t)
        {
          LOGGER.debug("Unable to query isActive() for {}: {}", key, t.getMessage());
        }

        if (isActive)
        {
          // Attempt drain
          try
          {
            jss.drain(Duration.ofSeconds(5)); // Reduced timeout from 10 to 5
            LOGGER.info("Drain initiated for consumer: {}", key);
          }
          catch (IllegalStateException ise)
          {
            LOGGER.debug("Drain not possible for {}: {}", key, ise.getMessage());
          }
          catch (Throwable drainEx)
          {
            LOGGER.warn("Drain failed for {}: {}", key, drainEx.getMessage());
          }

          // Wait for drain to complete with timeout
          try
          {
            int attempts = 0;
            while (jss.isActive() && attempts < 10) // Reduced from 20 to 10
            {
              Thread.sleep(250);
              attempts++;
            }
            
            if (jss.isActive())
            {
              LOGGER.warn("Drain timeout for {}, forcing unsubscribe", key);
              try 
              { 
                jss.unsubscribe(); 
              } 
              catch (Throwable unsubEx) 
              {
                LOGGER.debug("Unsubscribe after timeout failed for {}", key);
              }
            }
            else
            {
              LOGGER.info("✅ Drain completed for consumer: {}", key);
            }
          }
          catch (InterruptedException ie)
          {
            Thread.currentThread().interrupt();
            LOGGER.debug("Interrupted while draining {}", key);
          }
        }
        else
        {
          // Subscription not active - just unsubscribe
          LOGGER.debug("Subscription not active for {} - skipping drain", key);
          try 
          { 
            jss.unsubscribe(); 
          } 
          catch (Throwable unsubEx) 
          {
            LOGGER.debug("Unsubscribe for inactive subscription {} failed", key);
          }
        }

        // Server-side cleanup (only if manager-created and connection active)
        try
        {
          if (ctx.connection != null && 
              ctx.connection.getStatus() == Connection.Status.CONNECTED)
          {
            deleteServerSideConsumer(ctx.connection, subject, consumerName);
          }
          else
          {
            LOGGER.debug("Skipping server-side deletion for {} (connection not active)", key);
          }
        }
        catch (Throwable t)
        {
          LOGGER.warn("Server-side deletion failed for {}: {}", key, t.getMessage());
        }
      }
      catch (Throwable e)
      {
        LOGGER.warn("Error during drain for {}: {}", key, e.getMessage());
        // Final cleanup attempt
        try 
        { 
          ctx.subscription.unsubscribe(); 
        } 
        catch (Throwable ignore) 
        {
          LOGGER.debug("Final unsubscribe failed for {}", key);
        }
      }

      return null;
    }).onComplete(ar -> {
      // Always decrement counter and remove from draining map
      activeDrainOperations.decrementAndGet();
      drainingConsumers.remove(key);

      // Only remove registry entry if manager created the consumer
      try
      {
        ConsumerDescriptor desc = consumerRegistry.get(key);
        if (desc != null && desc.isCreatedByManager())
        {
          consumerRegistry.remove(key);
          LOGGER.debug("Removed manager-created consumer registry entry for {}", key);
        }
        else
        {
          LOGGER.debug("Preserving registry entry for {} (admin-owned or missing)", key);
        }
      }
      catch (Throwable t)
      {
        LOGGER.warn("Error updating registry for {}: {}", key, t.getMessage());
      }

      if (ar.succeeded())
      {
        LOGGER.info("✅ Completed cleanup for: {}", key);
      }
      else
      {
        LOGGER.warn("Cleanup completed with errors for: {} - {}", key, 
          ar.cause() != null ? ar.cause().getMessage() : "unknown");
      }
    });
  }
*/
  
  /**
   * Invalidate all consumer subscriptions
   */
  private void invalidateAllConsumers()
  {
    LOGGER.info("Invalidating all consumer subscriptions...");

    Map<String, ConsumerContext> snapshot = new HashMap<>(consumerPool);

    int count = 0;
    for (Map.Entry<String, ConsumerContext> entry : snapshot.entrySet())
    {
      try { cleanupConsumerContext(entry.getKey(), entry.getValue()); } catch (Throwable t) { LOGGER.warn("Error cleaning up consumer {}: {}", entry.getKey(), t.getMessage(), t); }
      count++;
    }

    consumerPool.clear();
    LOGGER.info("Invalidated {} consumer subscriptions", count);

    if (count > 0)
    {
      Set<Connection> connectionsToFlush = new HashSet<>();
      for (ConsumerContext ctx : snapshot.values())
      {
        if (ctx != null && ctx.connection != null) connectionsToFlush.add(ctx.connection);
      }

      if (!connectionsToFlush.isEmpty())
      {
        try
        {
          workerExecutor.executeBlocking(() ->
          {
            for (Connection conn : connectionsToFlush)
            {
              if (conn == null) continue;
              try { if (conn.getStatus() != Connection.Status.CONNECTED) { continue; } } catch (Throwable ignored) {}
              int[] attemptsMs = new int[] { 100, 250, 500 };
              boolean ok = false;
              for (int tms : attemptsMs)
              {
                try { conn.flush(java.time.Duration.ofMillis(tms)); ok = true; break; } catch (Throwable flushEx) { try { Thread.sleep(20); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); } }
              }
              if (!ok)
              {
                try { conn.flush(java.time.Duration.ofSeconds(2)); } catch (Throwable fallbackEx) { LOGGER.warn("Fallback flush failed for {}: {}", System.identityHashCode(conn), fallbackEx.getMessage()); }
              }
            }
            return null;
          }).onComplete(ar -> {
            if (ar.succeeded()) LOGGER.debug("Completed flush of old connections after invalidation");
            else LOGGER.warn("Worker flush after invalidation failed: {}", ar.cause() != null ? ar.cause().getMessage() : "unknown");
          });
        }
        catch (Exception e)
        {
          LOGGER.warn("Failed to schedule flush task after invalidation: {}", e.getMessage(), e);
        }
      }
    }
  }

  /**
   * Delete consumer from JetStream server (guarded by createdByManager).
   */
  private void deleteServerSideConsumer( Connection conn, String subject, String consumerName )
  {
    if( conn == null || consumerName == null )
    {
      LOGGER.debug( "Cannot delete server consumer - missing connection or name" );
      return;
    }

    try
    {
      // Look up registry entry; if absent, be defensive and skip deletion
      // (avoids accidental deletion).
      String keyByDurable = subject + ":" + consumerName;
      String keyByQueue = subject + ":queue:" + consumerName;

      ConsumerDescriptor desc = consumerRegistry.get( keyByDurable );
      if( desc == null )
        desc = consumerRegistry.get( keyByQueue );

      if( desc == null )
      {
        LOGGER.debug( "No registry entry for consumer '{}'; skipping server-side deletion (defensive)", consumerName );
        return;
      }

      if( !desc.isCreatedByManager() )
      {
        LOGGER.debug( "Skipping server-side consumer deletion for admin-owned consumer: {}", consumerName );
        return;
      }

      if( conn.getStatus() != Connection.Status.CONNECTED )
      {
        LOGGER.debug( "Connection not active, skipping server-side consumer deletion for: {}", consumerName );
        return;
      }

      JetStreamManagement jsm = conn.jetStreamManagement();

      String streamName = findStreamForSubject( jsm, subject );

      if( streamName == null )
      {
        LOGGER.warn( "Could not find stream for subject: {} (consumer: {})", subject, consumerName );
        return;
      }

      jsm.deleteConsumer( streamName, consumerName );
      LOGGER.info( "🗑️  Deleted server-side consumer: {} from stream: {}", consumerName, streamName );
    }
    catch( io.nats.client.JetStreamApiException apiEx )
    {
      if( apiEx.getErrorCode() == 10014 )
        LOGGER.debug( "Server-side consumer {} already deleted or not found", consumerName );
      else
        LOGGER.warn( "JetStream API error deleting consumer {}: {}", consumerName, apiEx.getMessage() );
    }
    catch( Exception e )
    {
      LOGGER.warn( "Failed to delete server-side consumer {}: {}", consumerName, e.getMessage(), e );
    }
  }

  /**
   * Find which stream contains the given subject
   */
  private String findStreamForSubject(JetStreamManagement jsm, String subject)
  {
    try
    {
      List<StreamInfo> streams = jsm.getStreams();

      for (StreamInfo streamInfo : streams)
      {
        List<String> subjects = streamInfo.getConfiguration().getSubjects();
        for (String streamSubject : subjects)
        {
          if (subjectMatches(subject, streamSubject)) return streamInfo.getConfiguration().getName();
        }
      }
    }
    catch (Exception e)
    {
      LOGGER.warn("Error finding stream for subject {}: {}", subject, e.getMessage());
    }

    return null;
  }

  /**
   * Subject pattern matcher (supports * and >)
   */
  private boolean subjectMatches(String subject, String pattern)
  {
    if (subject.equals(pattern)) return true;

    String[] subjectTokens = subject.split("\\.");
    String[] patternTokens = pattern.split("\\.");

    if (pattern.endsWith(">"))
    {
      if (subjectTokens.length < patternTokens.length - 1) return false;
      for (int i = 0; i < patternTokens.length - 1; i++)
      {
        if (!patternTokens[i].equals("*") && !patternTokens[i].equals(subjectTokens[i])) return false;
      }
      return true;
    }
    else
    {
      if (subjectTokens.length != patternTokens.length) return false;
      for (int i = 0; i < patternTokens.length; i++)
      {
        if (!patternTokens[i].equals("*") && !patternTokens[i].equals(subjectTokens[i])) return false;
      }
      return true;
    }
  }

  private String extractConsumerName(String key)
  {
    int colonIndex = key.lastIndexOf(':');
    if (colonIndex > 0 && colonIndex < key.length() - 1) return key.substring(colonIndex + 1);
    return null;
  }

  private String extractSubject(String key)
  {
    int colonIndex = key.lastIndexOf(':');
    if (colonIndex > 0) return key.substring(0, colonIndex);
    return null;
  }

  /**
   * Get registered consumers (for recreation)
   */
  public Map<String, ConsumerDescriptor> getRegisteredConsumers()
  {
    return new HashMap<>(consumerRegistry);
  }

  private boolean isCertificateError(Exception e)
  {
    if (e == null || e.getMessage() == null) return false;
    String msg = e.getMessage().toLowerCase();
    return msg.contains("certificate") || msg.contains("ssl") || msg.contains("tls") || msg.contains("handshake");
  }

  public void shutdown()
  {
    LOGGER.info("Shutting down consumer pool");
    invalidateAllConsumers();
    consumerRegistry.clear();
    try { if (workerExecutor != null) workerExecutor.close(); } catch (Throwable t) { LOGGER.debug("Failed to close workerExecutor: {}", t.getMessage(), t); }
  }

  public long getCurrentGeneration()
  {
    return currentCertificateGeneration;
  }

//Monitoring method
 public int getActiveDrainOperationsCount()
 {
   return activeDrainOperations.get();
 }

 public Map<String, Object> getPoolHealthStatus()
 {
   Map<String, Object> health = new HashMap<>();
   
   health.put("currentGeneration", currentCertificateGeneration);
   health.put("activeConsumers", consumerPool.size());
   health.put("registeredConsumers", consumerRegistry.size());
   health.put("drainingConsumers", drainingConsumers.size());
   health.put("activeDrainOperations", activeDrainOperations.get());
   
   // Count consumers by generation
   Map<Long, Integer> generationCounts = new HashMap<>();
   for (ConsumerContext ctx : consumerPool.values())
   {
     generationCounts.merge(ctx.generation, 1, Integer::sum);
   }
   health.put("consumersByGeneration", generationCounts);
   
   return health;
 }
 
  public Map<String, Object> getPoolStats()
  {
    Map<String, Object> stats = new HashMap<>();
    stats.put("currentGeneration", currentCertificateGeneration);
    stats.put("activeConsumers", consumerPool.size());
    stats.put("registeredConsumers", consumerRegistry.size());
    return stats;
  }
}