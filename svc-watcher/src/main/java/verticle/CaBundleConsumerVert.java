package verticle;


import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.KeySecretManager;
import core.model.CaBundle;
import core.model.ServiceCoreIF;
import core.processor.SignedMessageProcessor;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.nats.client.JetStreamSubscription;
import io.nats.client.Message;
import io.nats.client.MessageHandler;
import io.nats.client.Subscription;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;

import core.nats.NatsTLSClient;
import core.nats.NatsConsumerErrorHandler;
import processor.NatsCaBundleMsgProcessor;
import utils.WatcherConfig;

/**
 * Refactored CA Bundle consumer: - Single shared NatsCaBundleMsgProcessor
 * (stateless) - Single-flight rotation with epoch coalescing - Keeps only the
 * newest pending rotation - ACKs messages immediately (simplifies flow; can be
 * changed to deferred ACK if needed)
 */
public class CaBundleConsumerVert extends AbstractVerticle
{

  private static final Logger LOGGER = LoggerFactory.getLogger( CaBundleConsumerVert.class );
  private static final String SERVICE_ID = "watcher";

  private final KubernetesClient kubeClient;
  private final WatcherConfig config;
  private final NatsTLSClient natsTlsClient;
  private final KeySecretManager keyCache;
  private final String namespace;

  private WorkerExecutor workerExecutor;
  private Subscription   caSubscription;
  
  private final NatsConsumerErrorHandler errHandler;

  private NatsCaBundleMsgProcessor rotationProcessor;
  private SignedMessageProcessor epochExtractor;

  // Rotation coordination
  private final AtomicBoolean rotationInProgress = new AtomicBoolean( false );
  private volatile long currentEpoch = -1L;
  private final AtomicReference<Pending> pending = new AtomicReference<>( null );

  private static final class Pending
  {
    final long epoch;
    final byte[] raw;

    Pending( long epoch, byte[] raw )
    {
      this.epoch = epoch;
      this.raw = raw;
    }
  }

  public CaBundleConsumerVert( KubernetesClient kubeClient, NatsTLSClient natsTlsClient, KeySecretManager keyCache, WatcherConfig config, String namespace )
  {
    this.kubeClient = kubeClient;
    this.natsTlsClient = natsTlsClient;
    this.keyCache = keyCache;
    this.config = config;
    this.namespace = namespace;
    this.errHandler = new NatsConsumerErrorHandler();
  }

  @Override
  public void start( Promise<Void> startPromise )
  {
    LOGGER.info( "CaBundleConsumerVert.start() - Starting CA bundle consumer" );
    try
    {
      workerExecutor = vertx.createSharedWorkerExecutor( "ca-msg-handler", 8 );
      rotationProcessor = new NatsCaBundleMsgProcessor( vertx, workerExecutor, kubeClient, natsTlsClient, keyCache );
      epochExtractor = new SignedMessageProcessor( workerExecutor, keyCache );

      startCAConsumer().onSuccess( v -> {
        LOGGER.info( "CaBundleConsumerVert started successfully" );
        startPromise.complete();
      } ).onFailure( e -> {
        LOGGER.error( "Error starting CaBundleConsumerVert: {}", e.getMessage(), e );
        cleanup();
        startPromise.fail( e );
      } );
    }
    catch( Exception e )
    {
      startPromise.fail( e );
    }
  }

  @Override
  public void stop( Promise<Void> stopPromise )
  {
    LOGGER.info( "Stopping CaBundleConsumerVert" );
    cleanup();
    stopPromise.complete();
  }

  private void cleanup()
  {
    if( caSubscription != null )
    {
      try
      {
        if (caSubscription instanceof io.nats.client.JetStreamSubscription)
        {
          try { ((io.nats.client.JetStreamSubscription) caSubscription).drain( Duration.ofSeconds(2) ); } catch (Exception ignore) {}
        }
        caSubscription.unsubscribe();
      }
      catch( Exception e )
      {
        LOGGER.warn( "Error unsubscribing: {}", e.getMessage(), e );
      }
      caSubscription = null;
    }
    if( workerExecutor != null )
    {
      try
      {
        workerExecutor.close();
      }
      catch( Exception e )
      {
        LOGGER.warn( "Error closing worker executor: {}", e.getMessage(), e );
      }
      workerExecutor = null;
    }
    LOGGER.info( "CaBundleConsumerVert cleanup completed" );
  }
  
  private Future<Void> startCAConsumer()
  {
    LOGGER.info( "Starting CA Bundle JetStream consumer (attach to admin-created push consumer)" );

    Promise<Void> promise = Promise.promise();
    MessageHandler handler = createCAMessageHandler();

    // deliverSubject and queueGroup should match how the consumer was created
    // in Step-06:
    String deliverSubject = ServiceCoreIF.MetaDataClientCaCertStream; // e.g. "metadata.client.ca-cert"
    String queueGroup = "metadata-client-ca"; // matches admin-created deliver-group

    natsTlsClient.attachPushQueue( deliverSubject, queueGroup, handler )
                 .onSuccess( sub ->
                  {
                    this.caSubscription = sub; // no cast
                    if (sub instanceof io.nats.client.JetStreamSubscription) {
                      LOGGER.info( "CA Bundle consumer attached as JetStreamSubscription to {} queue {}", deliverSubject, queueGroup );
                    } else {
                      LOGGER.info( "CA Bundle consumer attached as plain NATS Subscription to {} queue {}", deliverSubject, queueGroup );
                    }
                    promise.complete();
                  })
                 .onFailure( err -> 
                  {
                    LOGGER.error( "Failed to attach CA consumer: {}", err.getMessage(), err );
                    cleanup();
                    promise.fail( err );
                  });

    return promise.future();
  }
  
  private MessageHandler createCAMessageHandler()
  {
    return ( Message msg ) -> {
      byte[] msgBytes = msg.getData();

      // Extract epoch asynchronously (do not block JetStream thread)
      extractEpoch( msgBytes ).onComplete( ar -> {
        if( ar.failed() )
        {
          LOGGER.error( "Epoch extraction failed: {}", ar.cause().getMessage(), ar.cause() );
          safeNak( msg );
          return;
        }
        long epoch = ar.result();
        if( epoch < 0 )
        {
          LOGGER.warn( "Invalid CA bundle epoch; ignoring" );
          safeAck( msg );
          return;
        }

        // Coordinate rotation
        scheduleOrQueue( epoch, msgBytes );

        // ACK early for simplicity (idempotent rotation assumed).
        // Change to deferred ack if you need stronger guarantees.
        safeAck( msg );
      } );
    };
  }
  
  private void scheduleOrQueue( long epoch, byte[] raw )
  {
    long cur = currentEpoch;
    if( epoch <= cur )
    {
      LOGGER.info( "Ignoring stale CA bundle epoch={} (currentEpoch={})", epoch, cur );
      return;
    }

    if( rotationInProgress.compareAndSet( false, true ) )
    {
      currentEpoch = epoch;
      LOGGER.info( "Starting rotation epoch={} (no active rotation)", epoch );
      startRotation( epoch, raw );
    }
    else
    {
      Pending prev = pending.get();
      while( true )
      {
        if( prev == null )
        {
          if( pending.compareAndSet( null, new Pending( epoch, raw ) ) )
          {
            LOGGER.info( "Queued rotation epoch={} (active rotation currentEpoch={})", epoch, currentEpoch );
            break;
          }
        }
        else
        {
          if( epoch > prev.epoch )
          {
            if( pending.compareAndSet( prev, new Pending( epoch, raw ) ) )
            {
              LOGGER.info( "Replaced queued rotation epoch={} with newer epoch={}", prev.epoch, epoch );
              break;
            }
          }
          else
          {
            LOGGER.info( "Discarding incoming epoch={} (<= queuedEpoch={}) while rotation active", epoch, prev.epoch );
            break;
          }
        }
        prev = pending.get();
      }
    }
  }
  
  private void startRotation( long epoch, byte[] raw )
  {
    rotationProcessor.processMsg( raw ).onComplete( ar -> {
      if( ar.failed() )
      {
        LOGGER.error( "Rotation failed epoch={} error={}", epoch, ar.cause() != null ? ar.cause().getMessage() : "unknown", ar.cause() );
      }
      Pending next = pending.getAndSet( null );
      if( next != null && next.epoch > currentEpoch )
      {
        LOGGER.info( "Promoting queued rotation epoch={} (previous epoch={})", next.epoch, currentEpoch );
        currentEpoch = next.epoch;
        // Continue without releasing rotationInProgress
        startRotation( next.epoch, next.raw );
        return;
      }
      rotationInProgress.set( false );
      LOGGER.info( "Rotation cycle ended epoch={} (no newer pending)", epoch );
    } );
  }

  private Future<Long> extractEpoch( byte[] signedBytes )
  {
    // We must decrypt/verify to access the CaBundle epoch
    return epochExtractor.obtainDomainObject( signedBytes ).compose( payload -> vertx.<Long> executeBlocking( () -> {
      CaBundle ca = CaBundle.deSerialize( payload );
      if( ca == null )
        return -1L;
      return ca.getCaEpochNumber();
    } ) );
  }

  private void safeAck( Message msg )
  {
    try
    {
      msg.ack();
    }
    catch( Exception e )
    {
      LOGGER.warn( "ACK failed: {}", e.getMessage() );
    }
  }

  private void safeNak( Message msg )
  {
    try
    {
      msg.nak();
    }
    catch( Exception e )
    {
      LOGGER.warn( "NAK failed: {}", e.getMessage() );
    }
  }

  /**
   * Recovery logic retained; can be adapted to reset state if needed.
   */
  @SuppressWarnings( "unused" )
  private void initiateRecovery()
  {
    LOGGER.info( "Initiating recovery deployment for CaBundleConsumerVert" );
    // (Your earlier recovery logic can be reintroduced here if desired.)
  }
}