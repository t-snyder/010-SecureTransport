package service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
//import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;

import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.eventbus.MessageConsumer;
import io.vertx.core.json.JsonObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.KeySecretManager;
import core.handler.VaultAccessHandler;
import core.model.ChildVerticle;
import core.model.ServiceCoreIF;

import core.nats.NatsTLSClient;
import core.verticle.KeyExchangeVert;
import core.verticle.VaultAppRoleSecretRotationVert;

import utils.WatcherConfig;

import verticle.CaBundleConsumerVert;

/**
 * Creates a secrets Watcher using the Kubernetes Client API to watch for specific events which are generally tls certificate renewal events and new certificates.
 * By capturing the change events on the TLS client certificates being managed by Cert-Manager the watcher publishes updated
 * renewal certificates to the MetaData Service which publishes the renewals to client services. 
 * 
 * Enhanced with NATS JetStream integration for client validation and authorization management.
 *
 * The Deployment of this service within a Kubernetes cluster (within the namespace) requires the following env variables to be set within the Deployment:
 *    kubeClusterName  = cluster name the ClusterWatcherVert is being deployed into. Used for publishing changes.
 *    watcherNameSpace = Namespace the watcher deployment is to. Used for validation and publishing changes.
 *    
 */
public class WatcherServiceMain
{
  private static final Logger LOGGER        = LoggerFactory.getLogger( WatcherServiceMain.class );

  // Default Values
  private static final String TlsCertPath   = "/app/certs/proxy/";   // Persistent volume mount path for TLS certs
  private static final String TlsCaPath     = "/app/certs/nats/";    // Persistent volume mount path for Vault NATS intermediate CA
  private static final String DefaultNS     = "nats";             
  private static final String ServiceId     = "watcher";
  private static final String MetadataId    = "metadata";
  private static final String CLIENT_CERT_SECRET_NAME = "watcher-tls-credential";

  private WatcherConfig watchConfig = null;
  private String        nameSpace   = null;
  private String        podName     = null;
  private String        tlsCertPath = null;
  private String        tlsCaPath   = null;
  
  private Vertx               vertx              = null;
  private KubernetesClient    kubeClient         = null;
  private NatsTLSClient       natsTlsClient      = null;
  private KeyExchangeVert     keyExchangeVert    = null;
  private KeySecretManager    keyCache           = null;
  private List<ChildVerticle> deployedVerticles  = new ArrayList<ChildVerticle>();
  private WorkerExecutor      workerExecutor     = null;

  // Replaces PulsarConsumerVert
  private CaBundleConsumerVert        caBundleVert       = null;

  private VaultAppRoleSecretRotationVert watcherAppRoleVert = null;
  private VaultAppRoleSecretRotationVert natsAppRoleVert    = null;
  private VaultAccessHandler             natsAccess         = null;
  private VaultAccessHandler             watcherAccess      = null;
  
  /**
   * The purpose of this class is to provide a kubernetes client API watch over 
   * specific kubernetes secrets 
   */
  public WatcherServiceMain() 
  {
    LOGGER.info("WatcherServiceMain.main() - Start");
    LOGGER.error("WatcherServiceMain.main() - Start (error)");

    try 
    {
      // Initialize Vertx with worker pool settings
      VertxOptions options = new VertxOptions()
          .setWorkerPoolSize(20)
          .setEventLoopPoolSize(4)
          .setMaxWorkerExecuteTime(120L * 1000 * 1000000) // 120 seconds in nanoseconds
          .setMaxWorkerExecuteTimeUnit(TimeUnit.NANOSECONDS)
          .setMaxEventLoopExecuteTime(10L * 1000 * 1000000) // 10 seconds in nanoseconds
          .setMaxEventLoopExecuteTimeUnit(TimeUnit.NANOSECONDS)
          .setBlockedThreadCheckInterval(5000) // Check every 5 seconds
          .setBlockedThreadCheckIntervalUnit(TimeUnit.MILLISECONDS);

      this.vertx = Vertx.vertx(options);
      
      try
      {
        String tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";
        String token = new String( java.nio.file.Files.readAllBytes( java.nio.file.Paths.get( tokenPath ) ), java.nio.charset.StandardCharsets.UTF_8 ).trim();

        Config apiConfig = new ConfigBuilder().withOauthToken( token ) // Explicitly
                                                                       // set
                                                                       // the
                                                                       // token
            .build();

        kubeClient = new KubernetesClientBuilder().withConfig( apiConfig ).build();

        LOGGER.info( "WatcherServiceMain.main() - Kubernetes client initialized with explicit OAuth token" );

        // Debug logging
        LOGGER.info( "=== Kubernetes Client Config Debug ===" );
        LOGGER.info( "Master URL: {}", apiConfig.getMasterUrl() );
        LOGGER.info( "Namespace: {}", apiConfig.getNamespace() );
        LOGGER.info( "OAuth Token set: {}", apiConfig.getOauthToken() != null );
        LOGGER.info( "OAuth Token length: {}", token.length() );
        LOGGER.info( "=== End K8s Client Config Debug ===" );
      }
      catch( Exception e )
      {
        LOGGER.error( "Failed to initialize Kubernetes client: {}", e.getMessage(), e );
        throw new RuntimeException( "Failed to initialize Kubernetes client", e );
      }
     
      // Check namespace file
      try
      {
        String nsPath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
        if( java.nio.file.Files.exists( java.nio.file.Paths.get( nsPath ) ) )
        {
          String ns = new String( java.nio.file.Files.readAllBytes( java.nio.file.Paths.get( nsPath ) ) );
          LOGGER.info( "ServiceAccount namespace file: {}", ns );
        }
      }
      catch( Exception e )
      {
        LOGGER.error( "Cannot read namespace file: {}", e.getMessage() );
      }

      LOGGER.info("=== End K8s Client Config Debug ===");
      this.nameSpace   = DefaultNS;
      this.podName     = getPodName();
      this.watchConfig = readConfig( kubeClient, nameSpace, "watcher-config" );

      validateAttributes();
      this.tlsCertPath = TlsCertPath;
      this.tlsCaPath   = TlsCaPath;
      LOGGER.info("WatcherServiceMain.main() - Cert Paths set - caPath = " + watchConfig.getCaCertFilePath() + "; certPath = " + watchConfig.getClientCertPath() );

      testNatsAccess();
 
      Map<String, String> natsConfig = Map.of(
          NatsTLSClient.NATS_URLS,             watchConfig.getNatsURL(),
          NatsTLSClient.NATS_CA_CERT_PATH,     watchConfig.getCaCertFilePath(),
          NatsTLSClient.NATS_CLIENT_CERT_PATH, watchConfig.getClientCertPath(),
          NatsTLSClient.NATS_CLIENT_SECRET,    watchConfig.getTLSSecret()
      );
       
//      Map<String, String> natsConfig = Map.of(
//          NatsTLSClient.NATS_URLS,             watchConfig.getNatsURL(),
//          NatsTLSClient.NATS_CA_CERT_PATH,     tlsCaPath + "/ca.crt",
//          NatsTLSClient.NATS_CLIENT_CERT_PATH, tlsCertPath + "/tls.crt",
//          NatsTLSClient.NATS_CLIENT_SECRET,    CLIENT_CERT_SECRET_NAME
//      );
        
      natsTlsClient = new NatsTLSClient( vertx, natsConfig, kubeClient, ServiceId, nameSpace );
      LOGGER.info("WatcherServiceMain.main() - NatsTLSClient created" );

      watcherAccess = new VaultAccessHandler( vertx, 
                                              watchConfig.getServiceId(),
                                              watchConfig.getWatcherAgentAddr(), 
                                              watchConfig.getVaultAgentHost(), 
                                              Integer.parseInt( watchConfig.getWatcherAgentPort() ),
                                              watchConfig.getWatcherAgentTokenPath());

      keyCache = new KeySecretManager( vertx, watcherAccess );
 
      String keyExchPublishTopic     = ServiceCoreIF.KeyExchangeStreamBase + MetadataId;
      String keyExchResponseTopic    = ServiceCoreIF.KeyExchangeStreamBase + ServiceId;
      String BundlePushConsumerTopic = ServiceCoreIF.BundlePushStreamBase  + ServiceId;
      
      // KeyExchangeVert will be deployed as a verticle later in deployPrerequisiteServices
      keyExchangeVert = new KeyExchangeVert( natsTlsClient, keyCache, ServiceId );
    }
    catch( Exception e )
    {
      String errMsg = "Error initializing WatcherServiceMain: " + e.getMessage();
      LOGGER.error( errMsg, e );
      throw new RuntimeException( errMsg );
    }
  }

  
  private void validateAttributes()
  {
    if( nameSpace == null || nameSpace.isEmpty() ) 
      throw new IllegalArgumentException( "Could not obtain namespace");

    if( podName == null || podName.isEmpty() ) 
      throw new IllegalArgumentException("POD_NAME environment variable must be set");
  
    if( watchConfig == null ) 
      throw new IllegalStateException("Failed to read watcher configuration");
  }

  private void testNatsAccess()
  {
    LOGGER.info("=== NATS CONNECTION DEBUG ===");
    LOGGER.info("NATS URL from config: {}", watchConfig.getNatsURL());
    LOGGER.info("TLS Cert Path: {}", tlsCertPath + "/tls.crt");
    LOGGER.info("TLS CA Path: {}", tlsCaPath + "/ca.crt");
    LOGGER.info("Client Secret Name: {}", CLIENT_CERT_SECRET_NAME);
    LOGGER.info("Namespace: {}", nameSpace);

    // Check if certificate files exist (they should be mounted as volumes)
    try 
    {
      java.nio.file.Path certPath = java.nio.file.Paths.get(tlsCertPath + "/tls.crt");
      java.nio.file.Path caPath = java.nio.file.Paths.get(tlsCaPath + "/ca.crt");
      java.nio.file.Path keyPath = java.nio.file.Paths.get(tlsCertPath + "/tls.key");
     
      LOGGER.info("TLS cert file exists: {}", java.nio.file.Files.exists(certPath));
      LOGGER.info("CA cert file exists: {}", java.nio.file.Files.exists(caPath));
      LOGGER.info("TLS key file exists: {}", java.nio.file.Files.exists(keyPath));
     
      if( java.nio.file.Files.exists(certPath )) 
      {
         LOGGER.info("TLS cert file size: {} bytes", java.nio.file.Files.size(certPath));
      }
      if (java.nio.file.Files.exists(caPath)) {
         LOGGER.info("CA cert file size: {}", java.nio.file.Files.size(caPath));
      }
      if (java.nio.file.Files.exists(keyPath)) {
         LOGGER.info("TLS key file size: {}", java.nio.file.Files.size(keyPath));
      }
    } 
    catch( Exception e ) 
    {
     LOGGER.warn("Error checking certificate files: {}", e.getMessage());
    }

    // Test basic connectivity to NATS (without TLS)
    String natsHost = extractHostFromUrl( watchConfig.getNatsURL() );
    if (natsHost != null) 
    {
      LOGGER.info("Attempting to resolve NATS host: {}", natsHost);
      try 
      {
         java.net.InetAddress address = java.net.InetAddress.getByName(natsHost);
         LOGGER.info("NATS host resolved to: {}", address.getHostAddress());
      } 
      catch (Exception e) {
         LOGGER.error("Cannot resolve NATS host {}: {}", natsHost, e.getMessage());
      }
    }

    LOGGER.info("=== END NATS DEBUG ===");
  }
  
  
  private String extractHostFromUrl( String url )
  {
    try
    {
      if( url.startsWith( "nats+tls://" ) )
      {
        return url.substring( "nats+tls://".length() ).split( ":" )[0];
      }
      else if( url.startsWith( "nats://" ) )
      {
        return url.substring( "nats://".length() ).split( ":" )[0];
      }
    }
    catch( Exception e )
    {
      LOGGER.warn( "Error extracting host from URL {}: {}", url, e.getMessage() );
    }
    return null;
  }
  
  /**
   * Starts the watcher service and initializes components
   */
  public void start() 
  {
    LOGGER.info("Starting Watcher Service...");

    workerExecutor = vertx.createSharedWorkerExecutor( "main", 3 );
   
    try 
    {
      deployServices();
    }
    catch( Exception e )
    {
      String errMsg = "Fatal error initializing WatcherServiceMain: " + e.getMessage();
      LOGGER.error( errMsg, e );
      cleanupResources();
      System.exit(1);
    }
  }
  
  /**
   * Stops the watcher service and cleans up resources
   */
  public void stop() 
  {
    LOGGER.info("Stopping Watcher Service...");
    cleanupResources();
  }
 
  private WatcherConfig readConfig( KubernetesClient client, String nameSpace, String name )
  {
    LOGGER.info("Reading configuration from configMap: {} in namespace: {}", name, nameSpace);

    ConfigMap config = client.configMaps().inNamespace( nameSpace ).withName( name ).get();

    if( config == null )
    {
      LOGGER.error( "ConfigMap not found: " + name );
      return null;
    }

    Map<String, String> configData = config.getData();

    watchConfig = new WatcherConfig( configData );
    LOGGER.info("Configuration read successfully");
    
    return watchConfig;
  }

  private String getPodName()
  {
    podName = System.getenv("POD_NAME");

    if( podName == null || podName.isEmpty() ) 
    {
      LOGGER.warn("POD_NAME environment variable is not set");
    }
    
    return podName;
  }

  private void cleanupResources()
  {
    LOGGER.info("Starting cleanup of resources");

    workerExecutor.executeBlocking(() -> 
    {
      try 
      {
        // Create a defensive copy to avoid concurrent modification
        List<ChildVerticle> verticlesToUndeploy = new ArrayList<>(deployedVerticles);
        
        // First undeploy all verticles in reverse order
        for(int i = verticlesToUndeploy.size() - 1; i >= 0; i--)
        {
          ChildVerticle child = verticlesToUndeploy.get(i);
          String vertInfo = child.vertName() + " with id = " + child.id();
      
          try 
          {
            LOGGER.info("Undeploying verticle: {}", vertInfo);
            vertx.undeploy(child.id()).toCompletionStage()
                 .toCompletableFuture()
                 .get(30, TimeUnit.SECONDS);
            LOGGER.info("Successfully undeployed verticle: {}", vertInfo);
          } 
          catch(TimeoutException e)
          {
            LOGGER.warn("Timeout while undeploying verticle {}: {}", vertInfo, e.getMessage());
          }
          catch(InterruptedException e) 
          {
            LOGGER.warn("Interrupted while undeploying verticle {}: {}", vertInfo, e.getMessage());
            Thread.currentThread().interrupt();
            break;
          }
          catch(Exception e) 
          {
            LOGGER.warn("Error while undeploying verticle {}: {}", vertInfo, e.getMessage(), e);
          }
        }
      
        deployedVerticles.clear();

        // Close the Kubernetes client
        if( kubeClient != null ) 
        {
          try 
          {
            kubeClient.close();
            LOGGER.info("Kubernetes client closed");
          } 
          catch(Exception e) 
          {
            LOGGER.warn("Error while closing Kubernetes client: {}", e.getMessage(), e);
          }
        }

        // Clean up NatsTLSClient
        if( natsTlsClient != null)
        {
          try
          {
            natsTlsClient.cleanup();
            LOGGER.info("NatsTLSClient cleaned up successfully");
          }
          catch(Exception e)
          {
            LOGGER.warn("Error closing natsTlsClient: {}", e.getMessage(), e);
          }
        }

        // Finally, close Vertx
        if(vertx != null) 
        {
          try 
          {
            vertx.close().toCompletionStage().toCompletableFuture().get(30, TimeUnit.SECONDS);
            LOGGER.info("Vertx instance closed");
          } 
          catch(Exception e) 
          {
            LOGGER.warn("Error while closing Vertx instance: {}", e.getMessage(), e);
          }
        }
      }
      catch(Exception e)
      {
        LOGGER.error("Error encountered cleaning up resources: {}", e.getMessage(), e);
      }

      return ServiceCoreIF.SUCCESS;
    }); 
  }
  
  
  private void deployServices()
  {
    workerExecutor.executeBlocking( () -> 
    {
      try 
      {
        deployNatsVerticles();

        // Deploying KeyExchangeVert
        DeploymentOptions options = new DeploymentOptions();
        options.setConfig( new JsonObject().put( "worker", true ));

        String deploymentIdKeyExchange = vertx.deployVerticle( keyExchangeVert, options )
                                              .toCompletionStage()
                                              .toCompletableFuture()
                                              .get( 30, TimeUnit.SECONDS );
        deployedVerticles.add( new ChildVerticle(keyExchangeVert.getClass().getName(), deploymentIdKeyExchange));

        LOGGER.info("KeyExchangeVert deployed successfully: {}", deploymentIdKeyExchange);

        // Wait for key exchange to signal completion, then deploy caBundleVert asynchronously (do NOT block the event-loop)
        waitForKeyExchangeComplete().onComplete( result -> 
        {
          if( !result.succeeded() ) 
          {
            LOGGER.error("Key exchange failed: {}", result.cause() != null ? result.cause().getMessage() : "unknown");
            cleanupResources();
            return;
          }

          // Non-blocking deployment of CaBundleConsumerVert (do NOT call .get() on completion stages here)
          try
          {
            DeploymentOptions natsOptions = new DeploymentOptions();
            natsOptions.setConfig( new JsonObject().put( "worker", true ) );

            caBundleVert = new CaBundleConsumerVert( kubeClient, natsTlsClient, keyCache, watchConfig, nameSpace );

            vertx.deployVerticle( caBundleVert, natsOptions )
              .onSuccess(deploymentIdCaBundle -> {
                deployedVerticles.add( new ChildVerticle( caBundleVert.getClass().getName(), deploymentIdCaBundle));
                LOGGER.info("CaBundleConsumerVert deployed successfully: {}", deploymentIdCaBundle);
              })
              .onFailure(deployErr -> {
                LOGGER.error("Failed to deploy CaBundleConsumerVert: {}", deployErr.getMessage(), deployErr);
                cleanupResources();
              });
          }
          catch( Exception e )
          {
            LOGGER.error("Error preparing CaBundleConsumerVert deployment: {}", e.getMessage(), e);
            cleanupResources();
          }

        });
      } 
      catch( Exception e ) 
      {
        LOGGER.error("Error during prerequisites: {}", e.getMessage(), e);
        cleanupResources();
      }
 
      return ServiceCoreIF.SUCCESS;
    });
  }
  
  private Future<String> waitForKeyExchangeComplete() 
  {
    Promise<String> promise = Promise.promise();
    
    MessageConsumer<byte[]> consumer = vertx.eventBus().consumer("metadata.keyExchange.complete", message -> 
    {
      String result = new String( message.body(), StandardCharsets.UTF_8 );
      LOGGER.info( "WatcherServiceMain.waitForKeyExchangeComplete - result = "+ result );

      if( ServiceCoreIF.SUCCESS.equals( result ))
      {
        promise.complete(result);
      } 
      else 
      {
        promise.fail("Key exchange failed: " + result);
      }
    });
    
    // Set timeout
    vertx.setTimer( 30000, id -> 
    {
      if( !promise.future().isComplete() ) 
      {
        promise.fail("Timeout waiting for key exchange");
      }
    });
    
    // Cleanup on completion
    promise.future().onComplete(ar -> consumer.unregister());
    
    return promise.future();
  }  

  /**
   * Deploys the verticles for the WatcherService.
   */
  private void deployNatsVerticles() 
   throws Exception 
  {
    DeploymentOptions natsOptions = new DeploymentOptions();
    natsOptions.setConfig( new JsonObject().put( "worker", true ) );

    try 
    {
      natsAccess = new VaultAccessHandler( vertx, 
                                             watchConfig.getServiceId(),
                                             watchConfig.getNatsAgentAddr(), 
                                             watchConfig.getVaultAgentHost(), 
                                             Integer.parseInt( watchConfig.getNatsAgentPort() ),
                                             watchConfig.getNatsAgentTokenPath());

      natsAppRoleVert = new VaultAppRoleSecretRotationVert( kubeClient, 
                                                              nameSpace, 
                                                              watchConfig.getNatsAppRoleSecretName(),
                                                              watchConfig.getNatsAppRoleName(),
                                                              Long.parseLong( watchConfig.getSecretIDRotationMs() ),
                                                              natsAccess ); 
      
      String deploymentIdNats = vertx.deployVerticle( natsAppRoleVert, natsOptions).toCompletionStage().toCompletableFuture().get(60, TimeUnit.SECONDS);
      deployedVerticles.add( new ChildVerticle( natsAppRoleVert.getClass().getName(), deploymentIdNats ));
      LOGGER.info("VaultAppRoleSecretRotationVert for nats-vault-approle deployed successfully: {}", deploymentIdNats);

      watcherAppRoleVert = new VaultAppRoleSecretRotationVert( kubeClient, 
                                                               nameSpace, 
                                                               watchConfig.getWatcherAppRoleSecretName(),
                                                               watchConfig.getWatcherAppRoleName(),
                                                               Long.parseLong( watchConfig.getSecretIDRotationMs() ),
                                                               watcherAccess ); 
      
      String deploymentIdWatcher = vertx.deployVerticle( watcherAppRoleVert, natsOptions).toCompletionStage().toCompletableFuture().get(60, TimeUnit.SECONDS);
      deployedVerticles.add( new ChildVerticle( watcherAppRoleVert.getClass().getName(), deploymentIdWatcher ));
      LOGGER.info("VaultAppRoleSecretRotationVert for watcher-vault-approle deployed successfully: {}", deploymentIdWatcher);

    } 
    catch( Exception e )
    {
      LOGGER.error("Fatal error deploying verticles: {}", e.getMessage(), e);
      throw e;
    }

    LOGGER.info("WatcherServiceMain.deployNatsVerticles() - Verticles deployed successfully");   
  }
  
  public KubernetesClient getKubernetesClient() { return kubeClient; }
   
  public static void main( String[] args )
  {
    LOGGER.info( "WatcherServiceMain.main - Starting WatcherService" );

    final WatcherServiceMain watcherSvc = new WatcherServiceMain();
    
    // Register shutdown hook for graceful shutdown
    Runtime.getRuntime().addShutdownHook( new Thread(() -> 
    {
      LOGGER.info( "Shutdown hook triggered - cleaning up resources" );
      watcherSvc.cleanupResources();
    }));
    
    watcherSvc.start();
  }
}