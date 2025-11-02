package processor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;
import utils.Fabric8NatsReloader;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;

import core.nats.NatsTLSClient;
import core.processor.SignedMessageProcessor;
import core.handler.KeySecretManager;
import core.model.CaBundle;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;

/**
 * CA bundle rotation with parallel NATS reload. Treats POSSIBLE_SUCCESS as
 * success so benign fast exec closures do not abort rotations.
 */
public class NatsCaBundleMsgProcessor
{

  private static final Logger LOGGER = LoggerFactory.getLogger( NatsCaBundleMsgProcessor.class );

  private static final String NATS_CA_SECRET_NAME = "nats-ca-tls";
  private static final String NATS_CA_SECRET_KEY = "ca.crt";

  private static final int SECRET_PROPAGATION_WAIT_SEC = 2;
  private static final int SERVER_RELOAD_WAIT_SEC = 2;
//  private static final int PARALLEL_RELOAD_TIMEOUT_SEC = 10;

  private final Vertx vertx;
  private final WorkerExecutor workerExecutor;
  private final KubernetesClient kubeClient;
  private final NatsTLSClient natsTlsClient;
  private final KeySecretManager keyCache;
  private final SignedMessageProcessor signedMsgProcessor;
  private final String namespace;
  private final Fabric8NatsReloader natsReloader;
  
  public NatsCaBundleMsgProcessor( Vertx vertx, WorkerExecutor workerExecutor, KubernetesClient kubeClient, NatsTLSClient natsTlsClient, KeySecretManager keyCache )
  {
    this.vertx              = vertx;
    this.workerExecutor     = workerExecutor;
    this.kubeClient         = kubeClient;
    this.natsTlsClient      = natsTlsClient;
    this.keyCache           = keyCache;
    this.namespace          = kubeClient.getNamespace();
    this.signedMsgProcessor = new SignedMessageProcessor( workerExecutor, this.keyCache );

    this.natsReloader = Fabric8NatsReloader.builder()
        .client(kubeClient.adapt(io.fabric8.kubernetes.client.KubernetesClient.class))
        .namespace(this.namespace)
        .containerName("nats")
        .useNatsServerSignal(true)
        .execTimeout(java.time.Duration.ofSeconds(5))
        .maxAttempts(1)          // increase if you want a retry
        .debug(false)            // set true temporarily if you want deep logs
        .build();
  }

  public Future<Void> processMsg( byte[] msgBytes )
  {
    final long rotationStart = System.currentTimeMillis();
 
    return obtainCaBundle( msgBytes ).compose( caBundle -> {
      long epoch = safeEpoch( caBundle );
      int certs = countCertificatesInBundle( caBundle.getCaBundle() );
      LOGGER.info( "╔═══════════════════════════════════════════════════════════╗" );
      LOGGER.info( "║  NATS CA BUNDLE ROTATION (epoch={}, certs={})                ║", epoch, certs );
      LOGGER.info( "╚═══════════════════════════════════════════════════════════╝" );

      return performRotation( caBundle ).onSuccess( v -> {
        long elapsed = System.currentTimeMillis() - rotationStart;
        LOGGER.info( "✅ Rotation success epoch={} elapsedMs={}", epoch, elapsed );
      } ).onFailure( err -> {
        long elapsed = System.currentTimeMillis() - rotationStart;
        LOGGER.error( "❌ Rotation failure epoch={} elapsedMs={} error={}", epoch, elapsed, err != null ? err.getMessage() : "unknown", err );
      } ).eventually( () -> {
        return Future.succeededFuture();
      } );
    } );
  }

  private Future<CaBundle> obtainCaBundle( byte[] signedMsgBytes )
  {
    return signedMsgProcessor.obtainDomainObject( signedMsgBytes ).compose( requestBytes -> workerExecutor.executeBlocking( () -> {
      CaBundle ca = CaBundle.deSerialize( requestBytes );
      if( ca == null || ca.getCaBundle() == null )
      {
        throw new RuntimeException( "Deserialized CaBundle is null/empty" );
      }
      return ca;
    } ) );
  }

  private Future<Void> performRotation(CaBundle caBundle)
  {
    long startTime = System.currentTimeMillis();
    String caContent = caBundle.getCaBundle();

    LOGGER.info("╔═══════════════════════════════════════════════════════════════╗");
    LOGGER.info("║ WATCHER: CA Rotation Orchestration Started                  ║");
    LOGGER.info("║ Epoch: {}                                                    ║", caBundle.getCaEpochNumber());
    LOGGER.info("╚═══════════════════════════════════════════════════════════════╝");

    return updateSecret(caContent)
      .compose(v -> {
        LOGGER.info("✅ Step 1: K8s secret updated");
        return waitAsync(SECRET_PROPAGATION_WAIT_SEC, "Secret propagation");
      })
      .compose(v -> {
        LOGGER.info("Step 2: Updating watcher's CA file");
        return updateWritableCaFile(caContent);
      })
      // NOTE: Move local NATS client notify AFTER we have signalled NATS servers to reload and waited.
      .compose(v -> {
        LOGGER.info("✅ Step 2: Watcher's CA file updated");
        LOGGER.info("Step 3: Sending SIGHUP to NATS pods");
        return sendReloadToPodsParallel();
      })
      .compose(v -> {
        LOGGER.info("✅ Step 3: SIGHUP sent to all NATS pods");
        LOGGER.info("Step 4: Waiting for NATS server reload");
        return waitAsync(SERVER_RELOAD_WAIT_SEC, "Server reload");
      })
      .compose(v -> {
        LOGGER.info("Step 5: Notifying local NATS client to handle CA update");
        try {
          return natsTlsClient.handleCaBundleUpdate(caBundle)
              .recover(err -> {
                LOGGER.warn("Local NATS client CA update failed (non-fatal): {}", err.getMessage());
                return Future.succeededFuture();
              });
        } catch (Exception e) {
          LOGGER.warn("Local NATS client CA update threw an exception (non-fatal): {}", e.getMessage());
          return Future.succeededFuture();
        }
      })
      .compose(v -> {
        long elapsed = System.currentTimeMillis() - startTime;
        
        LOGGER.info("╔═══════════════════════════════════════════════════════════════╗");
        LOGGER.info("║ ✅ WATCHER: CA Rotation Orchestration Complete              ║");
        LOGGER.info("║ Duration: {}ms                                               ║", elapsed);
        LOGGER.info("║                                                              ║");
        LOGGER.info("║ NATS servers reloaded - all clients will reconnect          ║");
        LOGGER.info("║ Watcher will reconnect automatically via ConnectionListener ║");
        LOGGER.info("╚═══════════════════════════════════════════════════════════════╝");
        
        return Future.succeededFuture();
      })
      .onFailure(err -> {
        long elapsed = System.currentTimeMillis() - startTime;
        LOGGER.error("❌ WATCHER: CA rotation failed after {}ms: {}", 
                    elapsed, err.getMessage(), err);
      })
      .mapEmpty();
  }
  
  private Future<String> updateSecret( String caBundleContent )
  {
    return vertx.executeBlocking( () -> {
      if( caBundleContent == null || caBundleContent.isBlank() )
      {
        throw new RuntimeException( "CA bundle empty" );
      }
      Secret existing = kubeClient.secrets().inNamespace( namespace ).withName( NATS_CA_SECRET_NAME ).get();
      if( existing == null )
      {
        throw new RuntimeException( "Secret " + NATS_CA_SECRET_NAME + " not found" );
      }

      Secret updated = kubeClient.secrets().inNamespace( namespace ).withName( NATS_CA_SECRET_NAME ).edit( current -> {
        SecretBuilder b = new SecretBuilder( current );
        b.addToStringData( NATS_CA_SECRET_KEY, caBundleContent );
        try
        {
          b.editMetadata().addToAnnotations( "rotation.watcher.io/ts", Instant.now().toString() ).endMetadata();
        }
        catch( Exception ignore )
        {
        }
        return b.build();
      } );

      LOGGER.info( "✅ Updated secret '{}'", NATS_CA_SECRET_NAME );
      return updated.getMetadata().getResourceVersion();
    } );
  }

  private Future<Void> updateWritableCaFile( String caBundleContent )
  {
    return vertx.executeBlocking( () -> {
      try
      {
        String path = natsTlsClient.getNatsCaPath();
        Path dest = Paths.get( path );
        Files.createDirectories( dest.getParent() );
        Path tmp = Paths.get( path + ".tmp" );
        Files.writeString( tmp, caBundleContent, StandardCharsets.UTF_8 );
        try
        {
          Files.move( tmp, dest, java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING );
        }
        catch( Exception fallback )
        {
          Files.move( tmp, dest, java.nio.file.StandardCopyOption.REPLACE_EXISTING );
        }
        LOGGER.info( "✅ Writable CA file updated: {}", dest );
      }
      catch( Exception e )
      {
        throw new RuntimeException( "Failed to write writable CA file", e );
      }
      return null;
    } ).mapEmpty();
  }
/**  
  private Future<Void> sendReloadToPodsParallel()
  {
    return vertx.executeBlocking( () -> {
      List<Pod> pods = kubeClient.pods().inNamespace( namespace ).withLabel( "app", "nats" ).list().getItems();
      if( pods.isEmpty() )
      {
        throw new RuntimeException( "No NATS pods found (label app=nats)" );
      }
      return pods;
    } ).compose( pods -> {

      List<Future<PodReloadResult>> tasks = new ArrayList<>( pods.size() );
      for( Pod p : pods )
      {
        String podName = p.getMetadata().getName();
        tasks.add( workerExecutor.executeBlocking( () -> {
          long start = System.currentTimeMillis();
          ReloadResult rr = execHelper.reload( podName, "nats" );
          return new PodReloadResult( podName, rr.outcome, rr.message, System.currentTimeMillis() - start );
        } ) );
      }

      return joinWithTimeout( tasks, PARALLEL_RELOAD_TIMEOUT_SEC * 1000L ).compose( results -> {
        long success = results.stream().filter( r -> r.outcome == ReloadOutcome.SUCCESS ).count();
        long possible = results.stream().filter( r -> r.outcome == ReloadOutcome.POSSIBLE_SUCCESS ).count();
        long hard = results.stream().filter( r -> r.outcome == ReloadOutcome.HARD_FAILURE ).count();

        LOGGER.info( "NATS reload summary: success={} possible={} hardFailures={} total={}", success, possible, hard, results.size() );

        if( hard > 0 )
        {
          results.stream().filter( r -> r.outcome == ReloadOutcome.HARD_FAILURE ).forEach( r -> LOGGER.warn( "Hard failure pod={} msg={}", r.podName, r.message ) );
        }

        long effectiveSuccess = success + possible;
        if( effectiveSuccess == 0 )
        {
          return Future.failedFuture( "All pod reloads failed (no success or possible success)" );
        }

        // OPTIONAL (async non-blocking verification):
        // vertx.executeBlocking(() -> { verifyLogs(results); return null; });

        return Future.succeededFuture();
      } );
    } );
  }
*/
  
  private Future<Void> sendReloadToPodsParallel()
  {
    return vertx.executeBlocking( () -> 
    {
      boolean any = natsReloader.reloadAll( "app", "nats" );
      if( !any )
      {
        throw new RuntimeException( "All pod reload attempts failed" );
      }
      return null;
    }).mapEmpty();
  }

/**  
  private <T> Future<List<T>> joinWithTimeout( List<Future<T>> futures, long timeoutMs )
  {
    Promise<List<T>> agg = Promise.promise();
    if( futures.isEmpty() )
    {
      agg.complete( Collections.emptyList() );
      return agg.future();
    }
    List<T> results = Collections.synchronizedList( new ArrayList<>( Collections.nCopies( futures.size(), null ) ) );
    AtomicInteger remaining = new AtomicInteger( futures.size() );

    for( int i = 0; i < futures.size(); i++ )
    {
      final int idx = i;
      futures.get( i ).onComplete( ar -> {
        if( !agg.future().isComplete() )
        {
          if( ar.succeeded() )
          {
            results.set( idx, ar.result() );
          }
          else
          {
            LOGGER.debug( "Task idx={} unexpected failure: {}", idx, ar.cause() != null ? ar.cause().getMessage() : "unknown" );
          }
          if( remaining.decrementAndGet() == 0 && !agg.future().isComplete() )
          {
            agg.complete( results );
          }
        }
      } );
    }

    long timerId = vertx.setTimer( timeoutMs, id -> {
      if( !agg.future().isComplete() )
      {
        agg.fail( "Timeout after " + timeoutMs + "ms waiting for reload tasks; remaining=" + remaining.get() );
      }
    } );

    agg.future().onComplete( done -> vertx.cancelTimer( timerId ) );
    return agg.future();
  }
*/
  
  private Future<Void> waitAsync( int seconds, String reason )
  {
    if( seconds <= 0 )
      return Future.succeededFuture();
    Promise<Void> p = Promise.promise();
    vertx.setTimer( seconds * 1000L, id -> {
      LOGGER.debug( "Wait complete: {} ({}s)", reason, seconds );
      p.complete();
    } );
    return p.future();
  }

  private long safeEpoch( CaBundle ca )
  {
    try
    {
      return ca.getCaEpochNumber();
    }
    catch( Exception e )
    {
      return -1;
    }
  }

  private int countCertificatesInBundle( String bundle )
  {
    if( bundle == null )
      return 0;
    int count = 0, idx = 0;
    final String marker = "-----BEGIN CERTIFICATE-----";
    while( ( idx = bundle.indexOf( marker, idx ) ) != -1 )
    {
      count++;
      idx += marker.length();
    }
    return count;
  }
/**
  private static final class PodReloadResult
  {
    final String podName;
    final ReloadOutcome outcome;
    final String message;
    final long elapsedMs;

    PodReloadResult( String podName, ReloadOutcome outcome, String message, long elapsedMs )
    {
      this.podName = podName;
      this.outcome = outcome;
      this.message = message;
      this.elapsedMs = elapsedMs;
    }
  }
*/  
}