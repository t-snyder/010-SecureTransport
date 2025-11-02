package verticle;

import java.security.SecureRandom;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.model.AuthenticationRequest;
import core.model.AuthenticationResponse;

import core.nats.NatsTLSClient;
import core.processor.SignedMessageProcessor;
import core.transport.SignedMessage;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.json.JsonObject;

import utils.AuthControllerConfig;

/**
 * AuthController producer that:
 * 1. Receives AuthenticationRequest (Avro bytes) from event bus
 * 2. Deserializes to AuthenticationRequest object
 * 3. Creates AuthenticationResponse
 * 4. Serializes AuthenticationResponse to Avro
 * 5. Uses SignedMessageProcessor to create SignedMessage
 * 6. Publishes SignedMessage to NATS response topic
 * 
 * Tracks processing counter and includes generation/receipt/processing counters in response.
 */
public class AuthControllerProducerVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger( AuthControllerProducerVert.class );

  private NatsTLSClient natsTlsClient = null;
  private SignedMessageProcessor signedMsgProcessor = null;
  private AuthControllerConfig authConfig = null;
  private WorkerExecutor workerExecutor = null;

  // Metrics
  private final AtomicLong messagesSent = new AtomicLong( 0 );
  private final AtomicLong messagesFailed = new AtomicLong( 0 );
  
  // Processing counter - tracks each message processed by this producer
  private final AtomicLong messageProcessingCounter = new AtomicLong( 0 );
  private long lastProcessingCounterLog = 0;

  private long lastMetricLog = System.currentTimeMillis();

  public AuthControllerProducerVert( NatsTLSClient natsTlsClient, SignedMessageProcessor signedMsgProcessor, AuthControllerConfig authConfig )
  {
    this.natsTlsClient = natsTlsClient;
    this.signedMsgProcessor = signedMsgProcessor;
    this.authConfig = authConfig;
  }

  @Override
  public void start( Promise<Void> startPromise ) throws Exception
  {
    LOGGER.info( "AuthControllerProducerVert.start() - Starting verticle" );

    workerExecutor = vertx.createSharedWorkerExecutor( "authcontroller-producer", 4 );

    try
    {
      setupEventBusHandlers();
      startMetricsReporting();

      startPromise.complete();
      LOGGER.info( "AuthControllerProducerVert.start() - Completed startup" );
    } 
    catch( Exception e )
    {
      LOGGER.error( "Error starting AuthControllerProducerVert: {}", e.getMessage(), e );
      cleanup();
      startPromise.fail( e );
    }
  }

  @Override
  public void stop( Promise<Void> stopPromise ) throws Exception
  {
    LOGGER.info( "AuthControllerProducerVert.stop() - Starting" );
    cleanup();
    stopPromise.complete();
    LOGGER.info( "AuthControllerProducerVert.stop() - Stopped successfully" );
  }

  /**
   * Setup event bus message handlers
   */
  private void setupEventBusHandlers()
  {
    // Handle authentication request messages from consumer
    vertx.eventBus().consumer( "authcontroller.process.request", message -> 
    {
      JsonObject request = (JsonObject)message.body();

      processAuthenticationRequest( request )
        .onSuccess( v -> {
          messagesSent.incrementAndGet();
        })
        .onFailure( err -> {
          messagesFailed.incrementAndGet();
          LOGGER.error( "Failed to process auth request: {}", err.getMessage(), err );
        });
    } );
  }

  /**
   * Process authentication request pipeline:
   * 1. Deserialize AuthenticationRequest from Avro bytes
   * 2. Create AuthenticationResponse
   * 3. Serialize AuthenticationResponse to Avro
   * 4. Create SignedMessage using SignedMessageProcessor
   * 5. Serialize SignedMessage
   * 6. Publish to NATS (with all counters in headers)
   */
  private Future<Void> processAuthenticationRequest( JsonObject request )
  {
    String messageKey = request.getString( "messageKey" );
    String originalMessageId = request.getString( "originalMessageId" );
    byte[] authRequestBytes = request.getBinary( "authRequestBytes" );
    Map<String, String> properties = convertJsonToMap( request.getJsonObject( "properties" ) );
    String responseTopic = request.getString( "topic" );
    
    // Extract counters from request
    Long receiptCounter = request.getLong( "receiptCounter" );
    Long generationCounter = request.getLong( "generationCounter" );
    
    // Increment processing counter for this message
    long processingCounter = messageProcessingCounter.incrementAndGet();
    
    // Log counters every 100 messages
    logProcessingCounterIfNeeded( processingCounter, generationCounter, receiptCounter );

    // Step 1: Deserialize AuthenticationRequest
    return workerExecutor.<AuthenticationRequest>executeBlocking( () -> 
        AuthenticationRequest.deserialize( authRequestBytes )
    )
    // Step 2: Create AuthenticationResponse
    .compose( authRequest -> workerExecutor.<AuthenticationResponse>executeBlocking( () -> 
        createAuthenticationResponse( authRequest, properties )
    ))
    // Step 3: Serialize AuthenticationResponse to Avro
    .compose( authResponse -> workerExecutor.<byte[]>executeBlocking( () -> 
        authResponse.serialize()
    ))
    // Step 4: Create SignedMessage
    .compose( authResponseBytes -> 
        signedMsgProcessor.createSignedMessage( 
            authConfig.getServiceId(),
            authResponseBytes,
            "AuthenticationResponse",
            "AuthenticationResponse",
            responseTopic
        )
    )
    // Step 5: Serialize SignedMessage
    .compose( signedMessage -> workerExecutor.<byte[]>executeBlocking( () -> 
        SignedMessage.serialize( signedMessage )
    ))
    // Step 6: Publish to NATS with all counters
    .compose( signedMessageBytes -> {
      // Add response metadata and counters to properties
      properties.put( "messageKey", messageKey );
      properties.put( "originalMessageId", originalMessageId );
      properties.put( "requestTimestamp", request.getLong( "requestTimestamp" ).toString() );
      properties.put( "responseTimestamp", String.valueOf( System.currentTimeMillis() ) );
      properties.put( "processingService", "authcontroller" );
      
      // Add all three counters to response headers
      if( generationCounter != null )
      {
        properties.put( "generationCounter", String.valueOf( generationCounter ) );
      }
      if( receiptCounter != null )
      {
        properties.put( "receiptCounter", String.valueOf( receiptCounter ) );
      }
      properties.put( "processingCounter", String.valueOf( processingCounter ) );

      return natsTlsClient.publish( responseTopic, signedMessageBytes, properties );
    })
    .onSuccess( v -> 
        LOGGER.debug( "Successfully published AuthenticationResponse for messageKey: {}", messageKey )
    )
    .onFailure( err -> 
        LOGGER.error( "Failed to publish AuthenticationResponse for messageKey: {}", messageKey, err )
    );
  }

  private void logProcessingCounterIfNeeded( long processingCounter, Long generationCounter, Long receiptCounter )
  {
    // Log every 100 messages
    if( processingCounter - lastProcessingCounterLog >= 100 )
    {
      if( generationCounter != null && receiptCounter != null )
      {
        LOGGER.info( "========== AUTHCONTROLLER MESSAGE PROCESSING: ProcessingCounter = {}, ReceiptCounter = {}, GenerationCounter = {} ==========", 
            processingCounter, receiptCounter, generationCounter );
      }
      else if( receiptCounter != null )
      {
        LOGGER.info( "========== AUTHCONTROLLER MESSAGE PROCESSING: ProcessingCounter = {}, ReceiptCounter = {}, GenerationCounter = N/A ==========", 
            processingCounter, receiptCounter );
      }
      else
      {
        LOGGER.info( "========== AUTHCONTROLLER MESSAGE PROCESSING: ProcessingCounter = {}, ReceiptCounter = N/A, GenerationCounter = N/A ==========", 
            processingCounter );
      }
      lastProcessingCounterLog = processingCounter;
    }
  }

  /**
   * Convert JsonObject to Map for message properties
   */
  private Map<String, String> convertJsonToMap( JsonObject jsonObject )
  {
    Map<String, String> map = new ConcurrentHashMap<>();
    if( jsonObject != null )
    {
      jsonObject.forEach( entry -> {
        map.put( entry.getKey(), entry.getValue().toString() );
      } );
    }
    return map;
  }

  /**
   * Create AuthenticationResponse based on AuthenticationRequest
   */
  private AuthenticationResponse createAuthenticationResponse( AuthenticationRequest authRequest, Map<String, String> properties )
  {
    AuthenticationResponse resp = new AuthenticationResponse();
    resp.setOid( UUID.randomUUID().toString() );
    resp.setUserToken( "token_" + authRequest.getUserId() + "_" + System.currentTimeMillis() );
    resp.setPasswordHash( authRequest.getPwdHash() );

    String result = determineAuthResult( authRequest );
    if( "APPROVED".equals( result ) )
    {
      resp.setIdentityToken( "identity_" + UUID.randomUUID() );
      resp.setIdentitySymmKey( randomBytes( 32 ) );
      resp.setIdentityIVSpec( randomBytes( 16 ) );
      resp.setAuthorizationToken( "auth_" + UUID.randomUUID() );
      resp.setAuthorizationSymmKey( randomBytes( 32 ) );
      resp.setAuthorizationIVSpec( randomBytes( 16 ) );
      resp.setAccountStatus( "ACTIVE" );
      resp.setMbrLevelCode( "STANDARD" );
    }
    else
    {
      resp.setAccountStatus( result );
      resp.setMbrLevelCode( "NONE" );
    }
    return resp;
  }

  /**
   * Determine authentication result based on request data
   */
  private String determineAuthResult( AuthenticationRequest authRequest )
  {
    String userId = authRequest.getUserId();
    String otp = authRequest.getOtp();
    
    if( userId == null || userId.isEmpty() )
      return "DENIED_NO_USER_ID";
    if( authRequest.getPwdHash() == null || authRequest.getPwdHash().isEmpty() )
      return "DENIED_NO_PASSWORD";
    if( userId.startsWith( "invalid_" ) )
      return "DENIED_INVALID_USER";
    if( otp != null && otp.startsWith( "expired_" ) )
      return "DENIED_OTP_EXPIRED";
    if( otp != null && otp.startsWith( "invalid_" ) )
      return "DENIED_INVALID_OTP";
    
    return "APPROVED";
  }

  /**
   * Generate random bytes for encryption keys
   */
  private byte[] randomBytes( int len )
  {
    byte[] b = new byte[len];
    new SecureRandom().nextBytes( b );
    return b;
  }

  /**
   * Start metrics reporting timer
   */
  private void startMetricsReporting()
  {
    vertx.setPeriodic( 60000, id -> {
      long currentTime = System.currentTimeMillis();
      long sent = messagesSent.get();
      long failed = messagesFailed.get();

      if( currentTime - lastMetricLog >= 60000 )
      {
        long elapsed = currentTime - lastMetricLog;
        long rate = elapsed > 0 ? ( sent * 60000 / elapsed ) : 0;
        
        LOGGER.info( "AuthController Producer Metrics - Messages sent: {}, failed: {}, rate: {}/min", 
            sent, failed, rate );

        lastMetricLog = currentTime;
      }
    } );
  }

  /**
   * Cleanup all resources
   */
  private void cleanup()
  {
    LOGGER.info( "AuthControllerProducerVert.cleanup() - Cleaning up resources" );

    if( workerExecutor != null )
    {
      try
      {
        workerExecutor.close();
        LOGGER.info( "Worker executor closed" );
      } 
      catch( Exception e )
      {
        LOGGER.warn( "Error closing worker executor: {}", e.getMessage(), e );
      }
    }

    LOGGER.info( "AuthControllerProducerVert.cleanup() - Cleanup completed" );
  }

  // Getters for metrics
  public long getMessagesSent() { return messagesSent.get(); }
  public long getMessagesFailed() { return messagesFailed.get(); }
  public long getMessageProcessingCounter() { return messageProcessingCounter.get(); }
}