package verticle;

import core.crypto.Argon2Hash;
import core.model.AuthenticationRequest;
import core.processor.SignedMessageProcessor;
import core.transport.SignedMessage;
import utils.GatekeeperConfig;
import core.nats.NatsTLSClient;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * NATS-based request generator. Periodically creates signed AuthenticationRequest 
 * messages with sequential counters and publishes them to the AuthController request subject.
 */
public class AuthRequestGeneratorVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger( AuthRequestGeneratorVert.class );

  private final NatsTLSClient natsTlsClient;
  private final SignedMessageProcessor msgProcessor;
  private final GatekeeperConfig config;

  private final int ratePerSecond;
  private final String targetSubject;
  private final int userCount;

  private WorkerExecutor workerExecutor;
  private final AtomicBoolean running = new AtomicBoolean( false );

  // Message generation counter - tracks each message created by this generator
  private final AtomicLong messageGenerationCounter = new AtomicLong( 0 );
  private long lastCounterLog = 0;

  public AuthRequestGeneratorVert( NatsTLSClient natsTlsClient, SignedMessageProcessor msgProcessor, GatekeeperConfig config )
  {
    this.natsTlsClient = natsTlsClient;
    this.msgProcessor = msgProcessor;
    this.config = config;
    this.ratePerSecond = config.getRatePerSecond();
    this.targetSubject = config.getAuthControllerRequestTopic();
    this.userCount = config.getUserCount();
  }

  @Override
  public void start( Promise<Void> startPromise )
  {
    try
    {
      LOGGER.info( "Starting AuthRequestGeneratorVert (NATS) rate={} subject={} userCount={}", 
          ratePerSecond, targetSubject, userCount );

      workerExecutor = vertx.createSharedWorkerExecutor( "auth-loadgen", 
                                                         5,        // poolSize
                                                         60_000,   // maxExecuteTime in ms
                                                         TimeUnit.MILLISECONDS
                                                       );
      
      running.set( true );
      startPeriodicSend();
      startPromise.complete();
      LOGGER.info( "AuthRequestGeneratorVert started." );
    }
    catch( Exception e )
    {
      LOGGER.error( "Failed to start AuthRequestGeneratorVert: {}", e.getMessage(), e );
      startPromise.fail( e );
    }
  }

  @Override
  public void stop( Promise<Void> stopPromise )
  {
    running.set( false );
    if( workerExecutor != null )
      workerExecutor.close();
    stopPromise.complete();
  }

  private void startPeriodicSend()
  {
    long timerInterval;
    int messagesPerTick;

    if( ratePerSecond >= 10 )
    {
      timerInterval = 100L;
      messagesPerTick = Math.max( 1, ratePerSecond / 10 );
    }
    else if( ratePerSecond > 0 )
    {
      timerInterval = 1000L / ratePerSecond;
      messagesPerTick = 1;
    }
    else
    {
      LOGGER.warn( "Invalid rate per second: {}. Load generation not started.", ratePerSecond );
      return;
    }

    LOGGER.info( "Periodic send configured interval={}ms messagesPerTick={}", timerInterval, messagesPerTick );

    vertx.setPeriodic( timerInterval, id -> {
      if( !running.get() )
      {
        vertx.cancelTimer( id );
        return;
      }
      for( int i = 0; i < messagesPerTick; i++ )
      {
        sendSingleAuthRequest()
         .onSuccess( t -> logCounterIfNeeded() )
         .onFailure( t -> LOGGER.debug( "AuthRequest send failed: {}", t.getMessage() ) );
      }
    } );
  }

  private Future<Void> sendSingleAuthRequest()
  {
    // Increment counter for this message
    long msgCounter = messageGenerationCounter.incrementAndGet();
    String userId = "user" + (int)( Math.random() * userCount );

    return workerExecutor.<String> executeBlocking( () -> Argon2Hash.hash( "secret" + userId ) )
        .compose( pwdHash -> {
          try
          {
            String otp = ( Math.random() < 0.8 ) ? String.format( "%06d", (int)( Math.random() * 1_000_000 ) ) : null;

            AuthenticationRequest request = new AuthenticationRequest( userId, pwdHash, otp );
            byte[] requestBytes = request.serialize();

            return msgProcessor.createSignedMessage( 
                config.getServiceId(), 
                requestBytes, 
                "authRequest", 
                "authRequest", 
                targetSubject );
          }
          catch( Exception e )
          {
            return Future.failedFuture( e );
          }
        } )
        .compose( ( SignedMessage signed ) -> workerExecutor.<byte[]> executeBlocking( () -> {
          try
          {
            return SignedMessage.serialize( signed );
          }
          catch( Exception e )
          {
            throw new RuntimeException( "Serialization failed", e );
          }
        } ) )
        .compose( serialized -> {
          Map<String, String> headers = new HashMap<>();
          headers.put( "messageType", "AuthenticationRequest" );
          headers.put( "encoding", "base64" );
          headers.put( "messageKey", "gen-" + System.nanoTime() );
          // Add generation counter to headers
          headers.put( "generationCounter", String.valueOf( msgCounter ) );
          headers.put( "generationTimestamp", String.valueOf( System.currentTimeMillis() ) );

          return natsTlsClient.publish( targetSubject, serialized, headers );
        } );
  }

  private void logCounterIfNeeded()
  {
    long current = messageGenerationCounter.get();
    // Log every 100 messages
    if( current - lastCounterLog >= 100 )
    {
      LOGGER.info( "========== GATEKEEPER MESSAGE GENERATION: Counter = {} ==========", current );
      lastCounterLog = current;
    }
  }

  public long getMessageGenerationCounter()
  {
    return messageGenerationCounter.get();
  }
}