package processor;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;
import io.fabric8.kubernetes.client.KubernetesClient;

import core.nats.NatsTLSClient;
import core.handler.KeySecretManager;
import core.model.CaBundle;
import core.model.ServiceCoreIF;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

/**
 * NATS-based CA Bundle Message Processor
 * 
 * Processes CA bundle rotation messages received from NATS JetStream. This
 * replaces the Pulsar-based message processor with NATS-specific handling.
 */
public class CaBundleMsgProcessor
{
  private static final Logger LOGGER = LoggerFactory.getLogger( CaBundleMsgProcessor.class );

  private final Vertx vertx;
  private final WorkerExecutor workerExecutor;
  private final KubernetesClient kubeClient;
  private final NatsTLSClient natsTlsClient;
  private final KeySecretManager keyCache;
  private final ObjectMapper objectMapper;

  public CaBundleMsgProcessor( Vertx vertx, WorkerExecutor workerExecutor, KubernetesClient kubeClient, NatsTLSClient natsTlsClient, KeySecretManager keyCache )
  {
    this.vertx = vertx;
    this.workerExecutor = workerExecutor;
    this.kubeClient = kubeClient;
    this.natsTlsClient = natsTlsClient;
    this.keyCache = keyCache;
    this.objectMapper = new ObjectMapper();
  }

  /**
   * Process CA bundle message received from NATS JetStream
   */
  public void processMsg( byte[] messageBytes )
  {
    LOGGER.info( "NatsCaBundleMsgProcessor.processMsg() - Processing CA bundle message" );

    try
    {
      if( messageBytes == null || messageBytes.length == 0 )
      {
        LOGGER.warn( "Received empty or null CA bundle message" );
        return;
      }

      String messageStr = new String( messageBytes, StandardCharsets.UTF_8 );
      LOGGER.debug( "Received CA bundle message: {} bytes", messageBytes.length );

      // Parse the message as CaBundle object
      CaBundle caBundle = parseMessage( messageStr );

      if( caBundle == null )
      {
        LOGGER.error( "Failed to parse CA bundle message" );
        return;
      }

      LOGGER.info( "Processing CA bundle update - Server: {}, Version: {}, Event: {}", caBundle.getServerId(), caBundle.getCaVersion(), caBundle.getEventType() );

      // Validate the CA bundle
      if( !isValidCaBundle( caBundle ) )
      {
        LOGGER.error( "Invalid CA bundle received - rejecting" );
        return;
      }

      // Process the CA bundle update asynchronously
      processCABundleUpdate( caBundle ).thenAccept( result -> {
        if( ServiceCoreIF.SUCCESS.equals( result ) )
        {
          LOGGER.info( "CA bundle processing completed successfully" );
        }
        else
        {
          LOGGER.error( "CA bundle processing failed: {}", result );
        }
      } ).exceptionally( throwable -> {
        LOGGER.error( "CA bundle processing failed with exception", throwable );
        return null;
      } );

    }
    catch( Exception e )
    {
      LOGGER.error( "Error processing CA bundle message", e );
      throw new RuntimeException( "CA bundle message processing failed", e );
    }
  }

  /**
   * Parse the message string into a CaBundle object
   */
  private CaBundle parseMessage( String messageStr )
  {
    try
    {
      // Try to parse as JSON first
      return objectMapper.readValue( messageStr, CaBundle.class );
    }
    catch( Exception jsonException )
    {
      LOGGER.debug( "Failed to parse as JSON, trying as raw CA bundle string", jsonException );

      try
      {
        // If JSON parsing fails, treat as raw CA bundle string
        // Create a CaBundle object with default metadata
        return new CaBundle( "nats-ca-update", java.time.Instant.now(), System.currentTimeMillis(), ServiceCoreIF.CaRotationEvent, messageStr, "nats-" + System.currentTimeMillis() );
      }
      catch( Exception e )
      {
        LOGGER.error( "Failed to parse CA bundle message as JSON or raw string", e );
        return null;
      }
    }
  }

  /**
   * Validate the CA bundle content
   */
  private boolean isValidCaBundle( CaBundle caBundle )
  {
    if( caBundle == null )
    {
      LOGGER.warn( "CA bundle is null" );
      return false;
    }

    if( caBundle.getCaBundle() == null || caBundle.getCaBundle().trim().isEmpty() )
    {
      LOGGER.warn( "CA bundle content is empty" );
      return false;
    }

    // Validate PEM format
    String caBundleContent = caBundle.getCaBundle();
    if( !caBundleContent.contains( "-----BEGIN CERTIFICATE-----" ) || !caBundleContent.contains( "-----END CERTIFICATE-----" ) )
    {
      LOGGER.warn( "CA bundle does not contain valid PEM certificates" );
      return false;
    }

    LOGGER.debug( "CA bundle validation passed" );
    return true;
  }

  /**
   * Process the CA bundle update using NatsTLSClient
   */
  private CompletableFuture<String> processCABundleUpdate( CaBundle caBundle )
  {
    CompletableFuture<String> future = new CompletableFuture<>();

    LOGGER.info( "Initiating CA bundle update with NatsTLSClient" );

    // Use NatsTLSClient to handle the CA bundle update
    natsTlsClient.handleCaBundleUpdate( caBundle ).onSuccess( result -> {
      LOGGER.info( "NatsTLSClient CA bundle update completed successfully" );

      // Optionally update key cache or perform additional processing
      updateKeyCache( caBundle ).thenAccept( cacheResult -> {
        LOGGER.debug( "Key cache update completed: {}", cacheResult );
        future.complete( ServiceCoreIF.SUCCESS );
      } ).exceptionally( cacheError -> {
        LOGGER.warn( "Key cache update failed, but CA update succeeded", cacheError );
        future.complete( ServiceCoreIF.SUCCESS ); // Don't fail overall process
        return null;
      } );
    } ).onFailure( error -> {
      LOGGER.error( "NatsTLSClient CA bundle update failed", error );
      future.complete( ServiceCoreIF.FAILURE );
    } );

    return future;
  }

  /**
   * Update the key cache with new CA information if needed
   */
  private CompletableFuture<String> updateKeyCache( CaBundle caBundle )
  {
    return CompletableFuture.supplyAsync( () -> {
      try
      {
        LOGGER.debug( "Updating key cache with new CA bundle information" );

        // Key cache updates if needed - this depends on your specific
        // implementation
        // For now, just log the update
        LOGGER.info( "Key cache notified of CA bundle update - Version: {}", caBundle.getCaVersion() );

        return ServiceCoreIF.SUCCESS;
      }
      catch( Exception e )
      {
        LOGGER.warn( "Failed to update key cache", e );
        return ServiceCoreIF.FAILURE;
      }
    } );
  }

  /**
   * Handle processing errors
   */
  private void handleProcessingError( String operation, Exception error )
  {
    LOGGER.error( "Error during {}: {}", operation, error.getMessage(), error );

    // Could implement retry logic, alerting, or other error handling here
    // For now, just log the error
  }

  /**
   * Get processing statistics (for monitoring)
   */
  public ProcessingStats getStats()
  {
    // Implementation would track processing metrics
    return new ProcessingStats();
  }

  /**
   * Simple stats class for monitoring
   */
  public static class ProcessingStats
  {
    private long totalMessagesProcessed = 0;
    private long totalProcessingErrors = 0;
    private long lastProcessedTimestamp = 0;

    // Getters and setters would go here
    public long getTotalMessagesProcessed()
    {
      return totalMessagesProcessed;
    }

    public long getTotalProcessingErrors()
    {
      return totalProcessingErrors;
    }

    public long getLastProcessedTimestamp()
    {
      return lastProcessedTimestamp;
    }
  }
}