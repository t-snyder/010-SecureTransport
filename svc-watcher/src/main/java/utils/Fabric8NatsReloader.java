package utils;


import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.ExecListener;
import io.fabric8.kubernetes.client.dsl.ExecWatch;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.OutputStream;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Quiet, Fabric8-based NATS reload helper (Fabric8 7.x compatible). Uses
 * 'nats-server --signal reload' (preferred) or 'kill -HUP 1'.
 *
 * Success heuristic: - If onOpen() is called, we assume the command started
 * (and for a very short reload signal that is enough). - Any post-open
 * failure/close is treated as success (fire-and-forget). - Timeout or pre-open
 * exception is treated as hard failure.
 */
public class Fabric8NatsReloader
{

  private static final Logger LOGGER = LoggerFactory.getLogger( Fabric8NatsReloader.class );

  private final KubernetesClient client;
  private final String namespace;
  private final String containerName;
  private final boolean useNatsServerSignal;
  private final Duration execTimeout;
  private final int maxAttempts;
  private final boolean debug;

  private Fabric8NatsReloader( Builder b )
  {
    this.client = Objects.requireNonNull( b.client, "client" );
    this.namespace = Objects.requireNonNull( b.namespace, "namespace" );
    this.containerName = Objects.requireNonNull( b.containerName, "containerName" );
    this.useNatsServerSignal = b.useNatsServerSignal;
    this.execTimeout = b.execTimeout;
    this.maxAttempts = b.maxAttempts;
    this.debug = b.debug;
  }

  public static Builder builder()
  {
    return new Builder();
  }

  /**
   * Reload all pods matching label key/value. Returns true if at least one
   * success.
   */
  public boolean reloadAll( String labelKey, String labelValue )
  {
    List<Pod> pods = client.pods().inNamespace( namespace ).withLabel( labelKey, labelValue ).list().getItems();

    if( pods == null || pods.isEmpty() )
    {
      LOGGER.warn( "No pods found selector {}={} ns={}", labelKey, labelValue, namespace );
      return false;
    }

    long successes = pods.stream().map( p -> reloadSinglePod( p.getMetadata().getName() ) ).filter( Boolean::booleanValue ).count();

    LOGGER.info( "NATS reload summary (Fabric8): success={} failure={} total={}", successes, pods.size() - successes, pods.size() );

    return successes > 0;
  }

  /**
   * Reload a single pod (best effort).
   */
  public boolean reloadSinglePod( String podName )
  {
    String[] cmd = useNatsServerSignal ? new String[] { "nats-server", "--signal", "reload" } : new String[] { "kill", "-HUP", "1" };

    for( int attempt = 1; attempt <= maxAttempts; attempt++ )
    {
      if( debug )
      {
        LOGGER.debug( "Reload attempt {}/{} pod={} cmd={}", attempt, maxAttempts, podName, String.join( " ", cmd ) );
      }
      boolean ok = doExec( podName, cmd );
      if( ok )
        return true;
      if( attempt < maxAttempts )
      {
        try
        {
          Thread.sleep( 200L );
        }
        catch( InterruptedException ie )
        {
          Thread.currentThread().interrupt();
          return false;
        }
      }
    }
    return false;
  }

  private boolean doExec( String podName, String[] cmd )
  {
    final CountDownLatch latch = new CountDownLatch( 1 );
    final ResultHolder result = new ResultHolder();
    OutputStream devNull = OutputStream.nullOutputStream();

    long startMs = System.currentTimeMillis();
    try( ExecWatch ignored = client.pods().inNamespace( namespace ).withName( podName ).inContainer( containerName ).writingOutput( devNull ).writingError( devNull ).writingErrorChannel( devNull ).usingListener( new ExecListener()
    {

      // Fabric8 7.x: onOpen() has NO parameters
      @Override
      public void onOpen()
      {
        result.opened = true;
        if( debug )
        {
          LOGGER.debug( "Exec opened pod={}", podName );
        }
      }

      @Override
      public void onFailure( Throwable t, Response response )
      {
        // Post-open failure is treated as benign if we opened
        if( debug )
        {
          LOGGER.debug( "Exec failure pod={} type={} msg={}", podName, t != null ? t.getClass().getSimpleName() : "null", t != null ? t.getMessage() : "null" );
        }
        latch.countDown();
      }

      @Override
      public void onClose( int code, String reason )
      {
        if( debug )
        {
          LOGGER.debug( "Exec closed pod={} code={} reason={}", podName, code, reason );
        }
        latch.countDown();
      }
    } ).exec( cmd ) )
    {

      boolean finished = latch.await( execTimeout.toMillis(), TimeUnit.MILLISECONDS );
      if( !finished )
      {
        if( debug )
          LOGGER.debug( "Exec timeout pod={} elapsedMs={}", podName, System.currentTimeMillis() - startMs );
        return false;
      }

      if( result.opened && !result.loggedSuccess )
      {
        LOGGER.info( "NATS reload signal (Fabric8) delivered pod={}", podName );
        result.loggedSuccess = true;
      }
      return result.opened;

    }
    catch( Exception e )
    {
      if( debug )
      {
        LOGGER.debug( "Exec exception pod={} type={} msg={}", podName, e.getClass().getSimpleName(), e.getMessage() );
      }
      // If channel opened before exception, count as success
      return result.opened;
    }
  }

  private static class ResultHolder
  {
    volatile boolean opened = false;
    volatile boolean loggedSuccess = false;
  }

  // ----------------------- Builder -----------------------
  public static final class Builder
  {
    private KubernetesClient client;
    private String namespace;
    private String containerName = "nats";
    private boolean useNatsServerSignal = true;
    private Duration execTimeout = Duration.ofSeconds( 5 );
    private int maxAttempts = 1;
    private boolean debug = false;

    public Builder client( KubernetesClient c )
    {
      this.client = c;
      return this;
    }

    public Builder namespace( String ns )
    {
      this.namespace = ns;
      return this;
    }

    public Builder containerName( String c )
    {
      this.containerName = c;
      return this;
    }

    public Builder useNatsServerSignal( boolean b )
    {
      this.useNatsServerSignal = b;
      return this;
    }

    public Builder execTimeout( Duration d )
    {
      this.execTimeout = d;
      return this;
    }

    public Builder maxAttempts( int a )
    {
      this.maxAttempts = a;
      return this;
    }

    public Builder debug( boolean d )
    {
      this.debug = d;
      return this;
    }

    public Fabric8NatsReloader build()
    {
      return new Fabric8NatsReloader( this );
    }
  }
}