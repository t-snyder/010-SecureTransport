package verticle;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.Watcher;
import io.fabric8.kubernetes.client.WatcherException;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;

import java.time.Instant;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import acl.DeclarativeACLParser;
import acl.ServicesACLMatrix;
import acl.ServicesACLConfig;
import acl.ServiceBundleManager;

import service.ServiceDilithiumKeyStore;
import service.TopicKeyGenerator;
import service.TopicKeyStore;

import core.handler.KeySecretManager;
import core.model.DilithiumKey;
import core.model.ServiceBundle;
import core.service.DilithiumKeyGenerator;
import core.utils.KeyEpochUtil;
import handler.MetadataVaultHandler;
import helper.MetadataConfig;

/**
 * ConfigMap-driven ACL watcher using declarative approach. Loads the ACL YAML from a ConfigMap and uses it to generate all service bundles.
 */
public class ServicesACLWatcherVert extends AbstractVerticle
{
  public static final String SERVICE_BUNDLE_REQUEST_ADDR = "service.bundle.request";
  public static final String METADATA__SIGNING_KEY_ADDR  = "metadata.signing.key.request";

  private static final Logger LOGGER = LoggerFactory.getLogger( ServicesACLWatcherVert.class );

//  private static final String ACL_CONFIGMAP_NAME_KEY = "aclConfigMapName";
//  private static final String ACL_CONFIGMAP_NAMESPACE_KEY = "aclNamespace";
  private static final String ACL_CONFIGMAP_DATA_KEY = "acl-manifest.yaml";
  private static final String ServiceId        = "metadata";

  private final KubernetesClient kubeClient;
  private final MetadataConfig   metadataConfig;
  private final KeySecretManager keyCache;
  private final MetadataVaultHandler vaultHandler;

  private WorkerExecutor           workerExecutor;
  private DeclarativeACLParser     declarativeParser;
  private ServiceBundleManager     bundleManager;
  private TopicKeyGenerator        topicKeyGenerator;
  private TopicKeyStore            topicKeyStore;
  private ServiceDilithiumKeyStore dilithiumKeyStore;
  private DilithiumKeyGenerator    dilithiumKeyGenerator;

  // The current state of the ACL matrix (source of truth for all bundle generation)
  private ServicesACLMatrix currentMatrix;
  private long periodicTimerId = -1;

  public ServicesACLWatcherVert( KeySecretManager keyCache, KubernetesClient kubernetesClient, MetadataVaultHandler vaultHandler, MetadataConfig metadataConfig )
  {
    this.keyCache        = keyCache;
    this.kubeClient      = kubernetesClient;
    this.vaultHandler    = vaultHandler;
    this.metadataConfig  = metadataConfig;
    this.currentMatrix   = new ServicesACLMatrix();
    LOGGER.info( "ConfigMap-driven ACL Watcher created - will load YAML from ConfigMap" );
  }

  @Override
  public void start( Promise<Void> startPromise )
  {
    try
    {
      workerExecutor        = vertx.createSharedWorkerExecutor( "declarative-acl-watcher", 2, 360000 );
      declarativeParser     = new DeclarativeACLParser( vertx );
      topicKeyGenerator     = new TopicKeyGenerator();
      topicKeyStore         = new TopicKeyStore( topicKeyGenerator );
      dilithiumKeyGenerator = new DilithiumKeyGenerator();
      dilithiumKeyStore     = new ServiceDilithiumKeyStore(dilithiumKeyGenerator);
      bundleManager         = new ServiceBundleManager( vertx, topicKeyStore, dilithiumKeyStore );

      processInitialConfigMap();
      startConfigMapWatcher();
      initializeEventBusConsumers();
      initializeMetadataServiceBundle();
      startEpochAlignedKeyRefresh();

      startPromise.complete();
      LOGGER.info( "ConfigMap-driven ACL Watcher started successfully" );
    }
    catch( Exception e )
    {
      LOGGER.error( "Failed to start ServicesACLWatcherVert: {}", e.getMessage(), e );
      startPromise.fail( e );
    }
  }

  private void processInitialConfigMap()
  {
    String configMapName = metadataConfig.getServicesACL().getAclConfigMapName();
    String configMapNamespace = metadataConfig.getServicesACL().getAclNamespace();

    ConfigMap configMap = kubeClient.configMaps().inNamespace( configMapNamespace )
                                                 .withName( configMapName )
                                                 .get();

    if( configMap != null )
    {
      LOGGER.info( "Found initial ConfigMap: {}", configMap.getMetadata().getName() );
      processConfigMapChange( Watcher.Action.ADDED, configMap );
    }
    else
    {
      LOGGER.warn( "ConfigMap {} not found in namespace {}", configMapName, configMapNamespace );
    }
  }

  private void startConfigMapWatcher()
  {
    String configMapName = metadataConfig.getServicesACL().getAclConfigMapName();
    String configMapNamespace = metadataConfig.getServicesACL().getAclNamespace();

    LOGGER.info( "Starting declarative ConfigMap watcher: {} in namespace: {}", configMapName, configMapNamespace );

    kubeClient.configMaps().inNamespace( configMapNamespace )
                           .withName( configMapName )
                           .watch( new Watcher<ConfigMap>()
    {
      @Override
      public void eventReceived( Action action, ConfigMap configMap )
      {
        if( configMap == null || !configMapName.equals( configMap.getMetadata().getName() ) )
        {
          LOGGER.debug( "Ignoring ConfigMap event for: {}", configMap != null ? configMap.getMetadata().getName() : "null" );
          return;
        }
        LOGGER.debug( "Received ConfigMap event: {} for {}", action, configMapName );
        workerExecutor.executeBlocking( () -> {
          processConfigMapChange( action, configMap );
          return null;
        }).onFailure( err -> LOGGER.error( "ConfigMap processing failed", err ) );
      }

      @Override
      public void onClose( WatcherException cause )
      {
        if( cause != null )
        {
          LOGGER.error( "ConfigMap watcher closed with error", cause );
          // Restart watcher after delay
          vertx.setTimer( 5000, id ->
          {
            LOGGER.info( "Restarting ConfigMap watcher..." );
            workerExecutor.executeBlocking( () ->
            {
              startConfigMapWatcher();
              return null;
            });
          });
        }
        else
        {
          LOGGER.info( "ConfigMap watcher closed normally" );
        }
      }
    });
  }

  /**
   * Process ConfigMap changes: always parse YAML and use it to produce all bundles.
   */
  private void processConfigMapChange( Watcher.Action action, ConfigMap configMap )
  {
    Map<String, String> data = configMap.getData();
    if( data == null )
    {
      LOGGER.warn( "ConfigMap has no data" );
      return;
    }

    String aclYaml = data.get( ACL_CONFIGMAP_DATA_KEY );
    if( aclYaml == null || aclYaml.trim().isEmpty() )
    {
      LOGGER.warn( "No {} found in ConfigMap or YAML is empty", ACL_CONFIGMAP_DATA_KEY );
      return;
    }

    try
    {
      LOGGER.info( "Parsing ACL YAML and generating ServicesACLMatrix" );
      // Parse YAML to structured config and build new matrix
      declarativeParser.parseFromYaml(aclYaml)
      .onSuccess(config -> {
        try {
          ServicesACLMatrix matrix = new ServicesACLMatrix();
          for( String serviceId : config.getAllServices() )
          {
            for( String topic : config.getTopicsForService( serviceId ) )
            {
              Set<ServicesACLConfig.PermissionType> perms = config.getServiceTopicAccess( serviceId, topic );
              for( ServicesACLConfig.PermissionType perm : perms )
              {
                matrix.addPermission( serviceId, topic, perm.name().toLowerCase() ); // "produce"/"consume"
              }
            }
          }

          LOGGER.info( "Matrix generated: {} services, {} topics", 
                      matrix.getAllServices().size(), matrix.getAllTopics().size() );
          this.currentMatrix = matrix;

          // Reinitialize metadata service bundle with new matrix
          initializeMetadataServiceBundle();

          // Generate and distribute all bundles based on the new matrix
          generateAndDistributeBundles( matrix );
        }
        catch( Exception e )
        {
          LOGGER.error( "Failed to build matrix from parsed YAML", e );
        }
      })
      .onFailure( e ->
      {
        LOGGER.error( "Failed to parse ConfigMap ACL YAML", e );
      });

    }
    catch( Exception e )
    {
      LOGGER.error( "Failed to process ConfigMap change", e );
    }
  }
  
  /**
   * Generate and distribute ServiceBundles for all services in the matrix.
   * Now also stores bundles in OpenBao for bootstrap capability.
   */
  private void generateAndDistributeBundles( ServicesACLMatrix matrix )
  {
    try
    {
      LOGGER.info( "Generating ServiceBundles for all services in matrix" );
      for( String serviceId : matrix.getAllServices() )
      {
        bundleManager.generateServiceBundleOnDemand( serviceId, "update", matrix )
         .onSuccess( bundle -> 
          {
            LOGGER.info( "Generated ServiceBundle for service {}", serviceId );
            
            // Store bundle in OpenBao for bootstrap capability
            storeBundleInVault( serviceId, bundle.getKeyEpoch(), bundle )
              .onSuccess( v -> LOGGER.info( "Stored ServiceBundle in OpenBao for service {}", serviceId ))
              .onFailure( e -> LOGGER.error( "Failed to store ServiceBundle in OpenBao for service {}: {}", 
                                            serviceId, e.getMessage(), e ));
          })
         .onFailure( e -> 
          {
            LOGGER.error( "Failed to generate ServiceBundle for service: " + serviceId, e );
          });
      }
    } 
    catch( Exception e )
    {
      LOGGER.error( "Failed to generate or distribute ServiceBundles", e );
    }
  }
  
  /**
   * Store a ServiceBundle in OpenBao at the service-specific path.
   * ServiceBundle is stored as Avro-serialized bytes (Base64 encoded for KV v2 storage).
   * Path format: secret/data/service-bundles/{serviceId}
   */
  private Future<Void> storeBundleInVault( String serviceId, long keyEpoch, ServiceBundle bundle )
  {
    return vaultHandler.putServiceBundle( serviceId, keyEpoch, bundle);
/**
    return workerExecutor.executeBlocking( () ->
    {
      try
      {
        // Serialize the bundle using Avro
        byte[] avroBytes = ServiceBundle.serialize( bundle );
        
        // Encode as Base64 for KV v2 storage (KV v2 requires string values in JSON)
        String base64Bundle = java.util.Base64.getEncoder().encodeToString( avroBytes );
        
        // Prepare data with metadata for easier querying
        Map<String, String> bundleData = new HashMap<>();
        // Use "bundle" key (Base64 encoded Avro) — simplified key as requested
        bundleData.put( "bundle", base64Bundle );  // The actual Avro serialized bundle
        bundleData.put( "version", bundle.getVersion() );
        bundleData.put( "updateType", bundle.getUpdateType() );
        bundleData.put( "createdAt", bundle.getCreatedAt().toString() );
        bundleData.put( "status", bundle.getStatus() );
        bundleData.put( "format", "avro" );  // Indicate this is Avro format
        
        String vaultPath = SERVICE_BUNDLE_VAULT_PATH_PREFIX + serviceId;
        
        LOGGER.debug( "Storing Avro-serialized ServiceBundle for {} at vault path: {}/{} ({} bytes)", 
                     serviceId, SERVICE_BUNDLE_VAULT_MOUNT, vaultPath, avroBytes.length );
        
        return bundleData;
      }
      catch( Exception e )
      {
        LOGGER.error( "Failed to serialize ServiceBundle (Avro) for vault storage: {}", e.getMessage(), e );
        throw new RuntimeException( "Failed to serialize ServiceBundle", e );
      }
    })
    .compose( bundleData ->
    {
      String vaultPath = SERVICE_BUNDLE_VAULT_PATH_PREFIX + serviceId;
      return vaultHandler.putKvV2( SERVICE_BUNDLE_VAULT_MOUNT, vaultPath, bundleData );
    });
  */
  }
  
  private void initializeMetadataServiceBundle()
  {
    LOGGER.info( "Initializing metadata service bundle for self-service" );

    bundleManager.generateServiceBundleOnDemand( ServiceId, "initialization", currentMatrix )
      .onSuccess( bundle -> 
       {
         try
         {
           // Use existing comprehensive method - handles ALL key types!
           keyCache.loadFromServiceBundle( bundle );

           // Store metadata bundle in vault as well
           storeBundleInVault( ServiceId, bundle.getKeyEpoch(), bundle )
             .onSuccess( v -> LOGGER.info( "Stored metadata ServiceBundle in OpenBao" ))
             .onFailure( e -> LOGGER.warn( "Failed to store metadata ServiceBundle in OpenBao: {}", 
                                          e.getMessage(), e ));

           vertx.eventBus().publish( "metadata.service.ready", ServiceId );
           LOGGER.info( "Successfully initialized metadata service bundle" );
         } 
         catch( Exception e )
         {
           LOGGER.error( "Failed to cache metadata service bundle: {}", e.getMessage(), e );
         }
       })
      .onFailure( e -> 
       {
         LOGGER.error( "Failed to generate metadata service bundle: {}", e.getMessage(), e );
         throw new RuntimeException( "Cannot initialize metadata service without its own bundle", e );
       });
  }

  /**
   * Epoch-aligned key refresh - now refreshes ALL service bundles, not just metadata
   */
  private void startEpochAlignedKeyRefresh() 
  {
    LOGGER.info("Starting epoch-aligned key refresh scheduler");
   
    // Calculate time until next epoch boundary
    Instant now            = Instant.now();
    long    currentEpoch   = KeyEpochUtil.epochNumberForInstant( now);
    Instant nextEpochStart = KeyEpochUtil.epochStart( currentEpoch + 1 );
   
    // Schedule first refresh at next epoch boundary minus 5 minutes (for preparation)
    long delayToNextEpoch = nextEpochStart.toEpochMilli() - now.toEpochMilli() - (5 * 60 * 1000); // 5 min early
   
    if( delayToNextEpoch < 0 ) 
    {
      // We're already past the preparation time, schedule for next epoch
      nextEpochStart   = KeyEpochUtil.epochStart(currentEpoch + 2);
      delayToNextEpoch = nextEpochStart.toEpochMilli() - now.toEpochMilli() - (5 * 60 * 1000);
    }
   
    LOGGER.info( "First key refresh scheduled in {} ms (at {})", delayToNextEpoch, 
                 Instant.ofEpochMilli(now.toEpochMilli() + delayToNextEpoch));
   
    // Set timer for first refresh
    vertx.setTimer( delayToNextEpoch, id -> 
    {
       performKeyRefresh();
       
       // Now schedule periodic refresh every epoch (3 hours)
       periodicTimerId = vertx.setPeriodic( KeyEpochUtil.EPOCH_DURATION_MILLIS, periodicId -> 
       {
         performKeyRefresh();
       });
       
       LOGGER.info("Scheduled periodic key refresh every {} ms", KeyEpochUtil.EPOCH_DURATION_MILLIS);
    });
  } 
  
  /**
   * Perform key refresh for ALL services, not just metadata.
   * This ensures all service bundles are updated with new keys and stored in OpenBao.
   */
  private void performKeyRefresh() 
  {
    LOGGER.info("Performing epoch-aligned key refresh for all services");
    
    workerExecutor.executeBlocking(() -> 
    {
      try 
      {
        // Refresh metadata service keys first
        initializeMetadataServiceBundle();
        
        // Regenerate and store bundles for all services in the matrix
        if( currentMatrix != null )
        {
          generateAndDistributeBundles( currentMatrix );
        }
                      
        LOGGER.info("Key refresh completed for all services");
        return "SUCCESS";
      } 
      catch( Exception e ) 
      {
        LOGGER.error("Key refresh failed: {}", e.getMessage(), e);
        throw e;
      }
    })
    .onComplete( ar -> 
     {
       if( ar.succeeded() ) 
       {
         LOGGER.info("Key refresh completed successfully for all services");
       } 
       else 
       {
         LOGGER.error("Key refresh failed: {}", ar.cause().getMessage(), ar.cause());
       }
    });
  }  
  
  private void initializeEventBusConsumers()
  {
    vertx.eventBus().consumer( SERVICE_BUNDLE_REQUEST_ADDR, msg -> 
    {
      try 
      {
        String serviceId;
        Object body = msg.body();
        if( body instanceof String ) 
        {
          serviceId = (String) body;
        } 
        else if( body instanceof JsonObject ) 
        {
          serviceId = ((JsonObject) body).getString( "serviceId" );
        } 
        else 
        {
          msg.fail(400, "Missing or invalid serviceId");
          return;
        }

        bundleManager.generateServiceBundleOnDemand( serviceId, "update", currentMatrix)
         .onSuccess( bundle -> 
          {
            try 
            {
              byte[] avroBytes = ServiceBundle.serialize( bundle );
              msg.reply(io.vertx.core.buffer.Buffer.buffer( avroBytes ));
            } 
            catch( Exception e ) 
            {
              LOGGER.error("Failed to serialize ServiceBundle", e);
              msg.fail(500, "Failed to serialize ServiceBundle: " + e.getMessage());
            }
          })
         .onFailure( e -> 
          {
            LOGGER.error("Failed to generate ServiceBundle for service: " + serviceId, e);
            msg.fail(500, "Failed to generate ServiceBundle: " + e.getMessage());
          });

      } 
      catch( Exception e ) 
      {
        LOGGER.error("Failed to process ServiceBundle request", e);
        msg.fail(500, "Failed to process ServiceBundle request: " + e.getMessage());
      }
    });
 
    vertx.eventBus().consumer(METADATA__SIGNING_KEY_ADDR, msg -> 
    {
      retrieveSigningKeyWithRetry( msg, 0, 100 ); // Start with 100ms delay
    }); 
  }
 
  private void retrieveSigningKeyWithRetry( Message<?> msg, int attempt, long delayMs ) 
  {
    final int MAX_ATTEMPTS = 10;
    final long MAX_DELAY = 5000; // 5 seconds max delay
      
    try 
    {
      workerExecutor.executeBlocking( () -> 
      {
        Map<Long, DilithiumKey> signingKeys = dilithiumKeyStore.getAllValidKeysForService(ServiceId);
        long                    nowEpoch    = KeyEpochUtil.epochNumberForInstant( Instant.now() );
              
        if( signingKeys != null && signingKeys.containsKey( nowEpoch )) 
        {
          return signingKeys.get( nowEpoch );
        }
        return null;
      })
      .onSuccess( signKey -> 
      {
        if( signKey != null ) 
        {
          try 
          {
            byte[] avroBytes = DilithiumKey.serialize(signKey, "transport");
            msg.reply(io.vertx.core.buffer.Buffer.buffer(avroBytes));
          } 
          catch( Exception e ) 
          {
            LOGGER.error("Failed to serialize DilithiumKey", e);
            msg.fail(500, "Failed to serialize signing key: " + e.getMessage());
          }
        }
        else if( attempt < MAX_ATTEMPTS ) 
        {
          // Key not available yet, retry with exponential backoff
          long nextDelay = Math.min(delayMs * 2, MAX_DELAY);
          vertx.setTimer( delayMs, id -> 
          {
            LOGGER.debug("Retrying signing key retrieval, attempt {}/{}", attempt + 1, MAX_ATTEMPTS);
            retrieveSigningKeyWithRetry(msg, attempt + 1, nextDelay);
          });
        } 
        else 
        {
          LOGGER.warn("Signing key not available after {} attempts", MAX_ATTEMPTS);
          msg.fail(503, "Signing key not yet available, please retry later");
        }
      })
      .onFailure( e -> 
       {
         LOGGER.error("Failed to retrieve signing key", e);
          msg.fail(500, "Failed to retrieve signing key: " + e.getMessage());
       });
    } 
    catch( Exception e ) 
    {
      LOGGER.error("Failed to process signing key request", e);
      msg.fail(500, "Failed to process signing key request: " + e.getMessage());
    }
  } 
}