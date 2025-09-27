package verticle;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.CompositeFuture;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.json.JsonObject;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.KeySecretManager;
import core.handler.VaultAccessHandler;
import core.model.ChildVerticle;

import core.nats.NatsTLSClient;
import core.service.DilithiumService;
//import core.utils.KeyExchangeConfig;
import core.verticle.VaultAppRoleSecretRotationVert;
import handler.MetadataVaultHandler;
import helper.MetadataConfig;
import service.MetadataService;

/**
 * Main verticle for the Metadata Service, responsible for deploying
 * and managing child verticles.
 */
public class MetadataServiceVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger( MetadataServiceVert.class );

  private static final String AppRoleSecretName  = "metadata-vault-approle";
  private static final String AppRoleName        = "metadata";
  private static final String VaultAgentAddr     = "http://127.0.0.1:8100";
  private static final String VaultAgentHost     = "127.0.0.1";
  private static final String VaultAgentPort     = "8100";
  private static final String VaultTokenPath     = "/home/vault/token";    
  private static final String SecretIDRotationMs = "300000"; // 5 minutes in ms, 1/2 of secret ttl
  
  private MetadataService      svc            = null;
  private KubernetesClient     kubeClient     = null;
  private NatsTLSClient        natsTlsClient  = null;
  private WorkerExecutor       workerExecutor = null;
  private MetadataVaultHandler vaultHandler   = null;
  private VaultAccessHandler   accessHandler  = null;
  private KeySecretManager     keyCache       = null;
  private DilithiumService     signer         = null;
  private MetadataConfig       config         = null;
  private String               nameSpace      = null;
  
  /**
   * Constructs a new MetadataServiceVert.
   *
   * @param svc The metadata service instance
   * @param config Configuration map
   * @param nameSpace Current namespace
   * @throws Exception If initialization fails
   */
  public MetadataServiceVert( Vertx vertx, MetadataService svc, KubernetesClient kubeClient, MetadataConfig config, String nameSpace, NatsTLSClient natsTlsClient )
   throws Exception
  {
    if( config == null )
    {
      String msg = "config can not be null.";
      LOGGER.error( msg );
      throw new Exception( msg );
    }
    
    if(( nameSpace == null || nameSpace.length() == 0 ) )
    {
      String msg = "Could not obtain current namespace.";
      LOGGER.error( msg );
      throw new Exception( msg );
    }

    this.svc            = svc;
    this.kubeClient     = kubeClient;
    this.config         = config;
    this.nameSpace      = nameSpace;
    this.natsTlsClient  = natsTlsClient;

    String serviceId  = config.getServiceId();
    
    String vaultAgentAddr = (config.getVault().getVaultAgentAddr()   == null ) ? VaultAgentAddr : config.getVault().getVaultAgentAddr();
    String vaultAgentHost = (config.getVault().getVaultAgentHost()   == null ) ? VaultAgentHost : config.getVault().getVaultAgentHost();
    String vaultAgentPort = (config.getVault().getVaultAgentPort()   == null ) ? VaultAgentPort : config.getVault().getVaultAgentPort();
    String vaultTokenPath = (config.getVault().getAppRoleTokenPath() == null ) ? VaultTokenPath : config.getVault().getAppRoleTokenPath();
    int port = Integer.parseInt( vaultAgentPort );

    this.accessHandler = new VaultAccessHandler( vertx, serviceId, vaultAgentAddr, vaultAgentHost, port, vaultTokenPath );
    this.vaultHandler  = new MetadataVaultHandler( vertx, accessHandler );
    
    this.keyCache = new KeySecretManager( vertx, accessHandler );
  }
  
  @Override
  public void start( Promise<Void> startPromise )
   throws Exception
  {
    workerExecutor = vertx.createSharedWorkerExecutor( "msg-handler" );

    // Use Future composition for proper async handling
    deployVerticles()
     .compose(v -> Future.succeededFuture())
     .onSuccess(v -> 
      {
        LOGGER.info("MetadataServiceVert started successfully");
        startPromise.complete(); // Single completion point
      })
      .onFailure(throwable -> 
      {
        String msg = "Fatal error during verticle deployment: " + throwable.getMessage();
        LOGGER.error(msg, throwable);
        svc.cleanupResources();
        startPromise.fail(msg); // Single failure point
      });    
  }

  @Override
  public void stop( Promise<Void> stopPromise ) 
   throws Exception
  {
    LOGGER.info("Stopping MetadataServiceVert");
    cleanup();
    stopPromise.complete();
  }

  /**
   * Vertx.undeploy method performs the following:
   *  1. Locates the verticle instance associated with the provided deployment ID
   *  2. Calls the verticle's stop() method (which executes any cleanup code defined there)
   *  3. Removes the verticle from the Vert.x deployment registry
   *  4. Releases any resources associated with that verticle
   */
  private void cleanup()
  {
    // Close worker executor
    if( workerExecutor != null ) 
    {
      try 
      {
        workerExecutor.close();
        LOGGER.info("Closed worker executor");
      } 
      catch( Exception e ) 
      {
        LOGGER.warn("Error while closing worker executor: " + e.getMessage(), e);
      }
    }
    
    // Close NATS client
    if( natsTlsClient != null )
    {
      try
      {
        natsTlsClient.cleanup();
        LOGGER.info("Closed NATS client");
      }
      catch( Exception e ) 
      {
        LOGGER.warn("Error while closing NATS client: " + e.getMessage(), e);
      }
    }
 
    if( accessHandler != null ) 
    {
      accessHandler.close();
    }

    LOGGER.info("MetadataServiceVert cleanup completed");
  }
 
  /**
   * Deploys the core verticles needed for this service, including KeyExchangeVert.
   */
  private Future<Void> deployVerticles() throws Exception
  {
    DeploymentOptions workerOptions    = new DeploymentOptions().setConfig(new JsonObject().put("worker", true));
    DeploymentOptions eventLoopOptions = new DeploymentOptions(); // default for event loop

    List<ChildVerticle> childDeployments  = svc.getDeployedVerticles();
    Promise<Void>       deploymentPromise = Promise.promise();

    workerExecutor.executeBlocking(() -> 
    {
      try 
      {
        ServicesACLWatcherVert aclWatcherVert   = new ServicesACLWatcherVert( keyCache, kubeClient, vaultHandler, config );
        Future<String>         aclWatcherFuture = deployVerticle( aclWatcherVert, workerOptions, "ServicesACLsWatcherVert");
        
        MetadataKeyExchangeVert keyExchangeVert   = new MetadataKeyExchangeVert( natsTlsClient, keyCache );
        Future<String>          keyExchangeFuture = deployVerticle( keyExchangeVert, workerOptions, "KeyExchangeVert");

        // Deploy MetadataClientConsumerVert
        MetadataClientConsumerVert mdConsumerVert = new MetadataClientConsumerVert( natsTlsClient );
        Future<String> mdConsumerFuture = deployVerticle(mdConsumerVert, workerOptions, "MetadataClientConsumerVert");

        // Deploy VaultAppRoleSecretRotationVert
        String appRoleSecretName  = ( config.getVault().getAppRoleSecretName()  == null ) ? AppRoleSecretName  : config.getVault().getAppRoleSecretName();
        String appRoleName        = ( config.getVault().getAppRoleName()        == null ) ? AppRoleName        : config.getVault().getAppRoleName();
        String secretIDRotationMs = ( config.getVault().getSecretIDRotationMs() == null ) ? SecretIDRotationMs : config.getVault().getSecretIDRotationMs();
        long   rotationMs         = Long.parseLong( secretIDRotationMs );

        VaultAppRoleSecretRotationVert appRoleRotator = new VaultAppRoleSecretRotationVert( kubeClient, 
                                                                                            nameSpace, 
                                                                                            appRoleSecretName, 
                                                                                            appRoleName, 
                                                                                            rotationMs,
                                                                                            accessHandler ); 

        Future<String> secretRotationFuture = deployVerticle(appRoleRotator, eventLoopOptions, "VaultAppRoleSecretRotationVert");

        this.signer = new DilithiumService( workerExecutor );

        CaRotatorVert caVert        = new CaRotatorVert( vertx, kubeClient, natsTlsClient, vaultHandler, config, signer, keyCache );
        Future<String> caVertFuture = deployVerticle( caVert, eventLoopOptions, "CaRotatorVert" );
       
        // Wait for all deployments to complete
        return Future.all( keyExchangeFuture,
                           mdConsumerFuture,
                           secretRotationFuture,
                           aclWatcherFuture,
                           caVertFuture
                         );
      } 
      catch( Exception e ) 
      {
        String msg = "Fatal error during NATS verticles deployment";
        LOGGER.error(msg, e);
        svc.cleanupResources();
        throw new RuntimeException(msg, e);
      }
    }).onComplete(ar -> 
       {
         if( ar.succeeded() ) 
         {
           CompositeFuture compositeFuture = (CompositeFuture) ar.result();
           String[] verticleNames = { "KeyExchangeVert", "MetadataClientConsumerVert", 
                                      "VaultAppRoleSecretRotationVert", "ServicesACLsWatcherVert", 
                                      "CaRotatorVert"
                                    };
           for( int i = 0; i < compositeFuture.size(); i++ ) 
           {
             String deploymentId = compositeFuture.resultAt(i);
             childDeployments.add(new ChildVerticle(verticleNames[i], deploymentId));
             LOGGER.info("{} deployed successfully: {}", verticleNames[i], deploymentId);
           }
        
           LOGGER.info("All NATS verticles deployed successfully");
           deploymentPromise.complete();
         } 
         else 
         {
           LOGGER.error("Worker execution failed: {}", ar.cause().getMessage());
           deploymentPromise.fail(ar.cause());
         }
       });

    return deploymentPromise.future();
  }
 
  // Helper method to deploy a single verticle
  private Future<String> deployVerticle( AbstractVerticle verticle, DeploymentOptions options, String name ) 
  {
    return vertx.deployVerticle( verticle, options )
                .onFailure(throwable -> LOGGER.error( "Failed to deploy {}: {}", name, throwable.getMessage() ));
  }
}