package core.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.VaultAccessHandler;
import core.model.CaBundle;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

/**
 * Example: Service retrieving CA bundles from Vault
 * 
 * This demonstrates how services can retrieve CA bundles from Vault
 * similar to how they retrieve ServiceBundles.
 */
public class ServiceCaBundleRetrieval
{
  private static final Logger LOGGER = LoggerFactory.getLogger( ServiceCaBundleRetrieval.class );

  private final Vertx              vertx;
  private final String             serviceId;
  private final VaultAccessHandler vaultHandler;
  
  public ServiceCaBundleRetrieval( Vertx vertx, String serviceId, VaultAccessHandler vaultHandler )
  {
    this.vertx        = vertx;
    this.serviceId    = serviceId;
    this.vaultHandler = vaultHandler;
  }
  
  /**
   * Retrieve the current CA bundle for a service on startup
   */
  public Future<CaBundle> bootstrapCaBundle( String serverId )
  {
    LOGGER.info( "Bootstrapping CA bundle for service: {}", serverId );

    return vaultHandler.getCurrentCaBundle( serverId )
      .onSuccess( bundle -> 
       {
         LOGGER.info( "Successfully retrieved current CA bundle for {} at epoch {}", serverId, bundle.getCaEpochNumber() );
       })
      .onFailure( err -> 
       {
         LOGGER.error( "Failed to bootstrap CA bundle for {}: {}", serverId, err.getMessage(), err );
       });
  }

  /**
   * Retrieve CA bundle for a specific epoch Useful when processing historical
   * messages or during rotation overlap
   */
  public Future<CaBundle> getCaBundleForEpoch( String serverId, long caEpoch )
  {
    LOGGER.info( "Retrieving CA bundle for {} at epoch {}", serverId, caEpoch );

    return vaultHandler.getCaBundle( serverId, caEpoch )
      .onSuccess( bundle -> 
       {
         LOGGER.info( "Successfully retrieved CA bundle for {} at epoch {}", serverId, caEpoch );
       })
      .onFailure( err -> 
       {
         LOGGER.warn( "CA bundle not found for {} at epoch {}: {}", serverId, caEpoch, err.getMessage() );
       });
  }

  /**
   * Retrieve all available CA bundles for a service Useful for maintaining a
   * local cache of recent CA bundles
   */
  public Future<List<CaBundle>> getAllCaBundles( String serverId )
  {
    LOGGER.info( "Retrieving all CA bundles for service: {}", serverId );

    return vaultHandler.getAllCaBundles( serverId )
      .onSuccess( bundles -> 
       {
         LOGGER.info( "Successfully retrieved {} CA bundles for {}", bundles.size(), serverId );

         // Log the epochs we have
         bundles.forEach( bundle -> LOGGER.debug( "  - CA bundle at epoch {}, version {}", bundle.getCaEpochNumber(), bundle.getCaVersion() ) );
       })
      .onFailure( err -> 
       {
         LOGGER.error( "Failed to retrieve CA bundles for {}: {}", serverId, err.getMessage(), err );
       });
  }

  /**
   * Example: Periodic sync of CA bundles from Vault Services can periodically
   * check for new CA bundles
   */
  public void startPeriodicCaBundleSync( String serverId, long intervalMs )
  {
    LOGGER.info( "Starting periodic CA bundle sync for {} every {} ms", serverId, intervalMs );

    vertx.setPeriodic( intervalMs, id -> 
    {
      vaultHandler.getCurrentCaBundle( serverId )
        .onSuccess( bundle -> 
         {
           long currentEpoch = bundle.getCaEpochNumber();
           LOGGER.debug( "Periodic sync: Current CA bundle epoch for {}: {}", serverId, currentEpoch );

           // Update local CA bundle if needed
           updateLocalCaBundle( bundle );
         })
        .onFailure( err -> 
         {
           LOGGER.warn( "Periodic CA bundle sync failed for {}: {}", serverId, err.getMessage() );
         });
    } );
  }

  private void updateLocalCaBundle( CaBundle bundle )
  {
    // Implementation depends on service-specific needs
    // Could update TLS context, write to file, update in-memory cache, etc.
    LOGGER.info( "Updating local CA bundle to epoch {}", bundle.getCaEpochNumber() );
  }
}