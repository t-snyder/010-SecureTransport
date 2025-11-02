package service;


import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

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
import core.processor.SignedMessageProcessor;
import core.nats.NatsTLSClient;
import core.verticle.KeyExchangeVert;
import core.verticle.VaultAppRoleSecretRotationVert;
import core.verticle.CABundleUpdateVert;

import utils.AuthControllerConfig;
import verticle.AuthControllerProducerVert;
import verticle.AuthControllerConsumerVert;

import core.utils.CAEpochUtil;
import core.utils.KeyEpochUtil;
import core.model.CaBundle;
import core.model.ServiceBundle;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

/**
 * AuthController Service Main - A microservice for authentication processing
 * that consumes requests from Gatekeeper service and sends back auth responses. The two 
 * services purpose is to provide a testbed for testing the functionality and resiliency
 * of the encryption and signing key rotation as well as the pulsar ca certificate bundle
 * rotation.
 * 
 * Features: 1. Key exchange with metadata service using KeyExchangeVert 
 *           2. Periodic key rotation 
 *           3. Authentication request processing from Gatekeeper 
 *           4. Authentication response sending back to Gatekeeper 
 *           5. CA Bundle updates for certificate rotation 
 *           6. Comprehensive downtime tracking and monitoring 
 *           7. Health monitoring and metrics collection
 */
public class AuthControllerServiceMain
{
  private static final Logger LOGGER = LoggerFactory.getLogger( AuthControllerServiceMain.class );

  // Default Values
  private static final String TlsCertPath = "/app/certs/proxy/";
  private static final String TlsCaPath   = "/app/certs/ca/";
  private static final String ServiceId   = "authcontroller";
  private static final String MetadataId  = "metadata";
  private static final String CLIENT_CERT_SECRET_NAME = "authcontroller-tls-credential";

  private AuthControllerConfig authConfig = null;
  private String nameSpace   = null;
  private String podName     = null;
  private String tlsCertPath = null;
  private String tlsCaPath   = null;

  private Vertx               vertx             = null;
  private KubernetesClient    kubeClient        = null;
  private NatsTLSClient       natsTlsClient     = null;
  private KeySecretManager    keyCache          = null;
  private List<ChildVerticle> deployedVerticles = new ArrayList<ChildVerticle>();
  private WorkerExecutor      workerExecutor    = null;

  private KeyExchangeVert                keyExchangeVert           = null;
  private CABundleUpdateVert             caBundleUpdateVert        = null;
  private AuthControllerProducerVert     producerVert              = null;
  private AuthControllerConsumerVert     consumerVert              = null;
  private VaultAppRoleSecretRotationVert authControllerAppRoleVert = null;
  private VaultAccessHandler             authControllerAccess      = null;
  private SignedMessageProcessor         signedMsgProcessor        = null;
  private MessageConsumer<JsonObject>    tlsExceptionConsumer      = null;
  
  /**
   * Initialize the AuthController Service with all required components
   */
  public AuthControllerServiceMain()
  {
    try
    {
      // Initialize Vertx with optimized settings for high-throughput messaging
      VertxOptions options = new VertxOptions().setWorkerPoolSize( 32 )
                                               .setEventLoopPoolSize( 8 )
                                               // Ensure the worker time limit is actually 60s
                                               .setMaxWorkerExecuteTimeUnit( TimeUnit.MILLISECONDS )
                                               .setMaxWorkerExecuteTime( 60000 );
      this.vertx = Vertx.vertx( options );

      // Create Kubernetes client
      Config apiConfig = new ConfigBuilder().build();
      kubeClient = new KubernetesClientBuilder().withConfig( apiConfig ).build();

      LOGGER.info( "AuthControllerServiceMain() - Kubernetes client initialized" );

      this.nameSpace  = kubeClient.getNamespace();
      this.podName    = getPodName();
      this.authConfig = readConfig( kubeClient, nameSpace, "authcontroller-config" );

      validateAttributes();

      this.tlsCertPath = TlsCertPath;
      this.tlsCaPath   = TlsCaPath;
      LOGGER.info( "AuthControllerServiceMain() - Cert Paths set - caPath = {} ; certPath = {}", authConfig.getCaCertPath(), authConfig.getClientCertPath() );

      
      Map<String, String> natsConfig = Map.of(
          NatsTLSClient.NATS_URLS,             authConfig.getNatsURL(),
          NatsTLSClient.NATS_CA_CERT_PATH,     authConfig.getCaCertPath(),
          NatsTLSClient.NATS_CLIENT_CERT_PATH, authConfig.getClientCertPath(),
          NatsTLSClient.NATS_CLIENT_SECRET,    authConfig.getTlsSecret()
      );

      natsTlsClient = new NatsTLSClient( vertx, natsConfig, kubeClient, ServiceId, nameSpace );
      LOGGER.info( "AuthControllerServiceMain() - NatsTLSClient created" );

      // Initialize Vault access handlers
      authControllerAccess = new VaultAccessHandler( vertx, authConfig.getServiceId(), authConfig.getAuthControllerAgentAddr(), authConfig.getBaoAgentHost(), Integer.parseInt( authConfig.getAuthControllerAgentPort() ),
                                                     authConfig.getAuthControllerAgentTokenPath() );

      keyCache = new KeySecretManager( vertx, authControllerAccess );

      // Create KeyExchangeVert for key management
      keyExchangeVert = new KeyExchangeVert( natsTlsClient, keyCache, ServiceId );

      // Create CABundleUpdateVert for certificate management
      caBundleUpdateVert = new CABundleUpdateVert( kubeClient, natsTlsClient, keyCache, ServiceId, nameSpace );

      workerExecutor     = vertx.createSharedWorkerExecutor( "main", 5 );
      signedMsgProcessor = new SignedMessageProcessor( workerExecutor, keyCache );
      
      // Register event bus listener to react to TLS / certificate-related exceptions
      registerTlsExceptionHandler();
       
    } 
    catch( Exception e )
    {
      String errMsg = "Error initializing AuthControllerServiceMain: " + e.getMessage();
      LOGGER.error( errMsg, e );
      throw new RuntimeException( errMsg );
    }
  }

  private void registerTlsExceptionHandler()
  {
    tlsExceptionConsumer = vertx.eventBus().consumer("nats.tls.exception", msg -> 
    {
      try 
      {
        JsonObject body = (JsonObject) msg.body();
        LOGGER.warn("Received nats.tls.exception event: {}", body);

        // Offload heavy work to a worker thread using Callable form (Vert.x 5)
        vertx.executeBlocking(() -> 
        {
          handleTlsException();          // blocking work
          return null;                   // Callable<Void> - return null
        })
        .onComplete(ar -> {
          if (ar.succeeded()) {
            LOGGER.debug("TLS exception handler completed successfully");
          } else {
            LOGGER.warn("TLS exception handler failed: {}", ar.cause() != null ? ar.cause().getMessage() : "unknown", ar.cause());
          }
        });

      } catch (Throwable t) {
        LOGGER.warn("Failed to process nats.tls.exception event: {}", t.getMessage(), t);
      }
    });
  }
  
  private void handleTlsException()
  {
    try
    {
      // Compute current CA epoch and key epoch
      CAEpochUtil caEpochUtil = new CAEpochUtil();
      long currentCaEpoch = caEpochUtil.epochNumberForInstant( Instant.now() );

      long keyEpoch = KeyEpochUtil.epochNumberForInstant( Instant.now() );

      LOGGER.info("Handling TLS exception: computed currentCaEpoch={}, keyEpoch={}", currentCaEpoch, keyEpoch);

      // Fetch current CA bundle from Vault
      authControllerAccess.getCurrentCaBundle("NATS")
        .onSuccess( caBundle -> {
          try {
            if (caBundle == null) {
              LOGGER.warn("No CA bundle returned from Vault for NATS");
              return;
            }

            // Compute hash of fetched CA bundle
            String fetchedHash = computeHash( caBundle.getCaBundle() );

            // Compare with NATS client's applied CA hash
            String appliedHash = natsTlsClient.getAppliedCaContentHash();
            if (appliedHash == null || !appliedHash.equals(fetchedHash))
            {
              LOGGER.info("Applied CA hash differs from Vault CA (applied={}, vault={}) - applying update", shortHash(appliedHash), shortHash(fetchedHash));
              // Apply CA bundle via nats client (it will perform verification and recreate)
              natsTlsClient.handleCaBundleUpdate(caBundle).onComplete(ar -> {
                if (ar.succeeded()) {
                  LOGGER.info("Applied new CA bundle from Vault successfully");
                } else {
                  LOGGER.error("Failed to apply CA bundle from Vault: {}", ar.cause() != null ? ar.cause().getMessage() : "unknown");
                }
              });
            } else {
              LOGGER.info("NATS client already has the current CA bundle applied");
            }
          } catch (Exception ex) {
            LOGGER.error("Error while comparing/applying CA bundle: {}", ex.getMessage(), ex);
          }
        })
        .onFailure(err -> {
          LOGGER.warn("Failed to retrieve CA bundle from Vault: {}", err.getMessage());
        });

      // Fetch latest ServiceBundle (signing/encryption keys) for this service for current keyEpoch
      authControllerAccess.getServiceBundle(ServiceId, keyEpoch)
        .onSuccess( bundle -> {
          if (bundle != null) {
            try {
              keyCache.loadFromServiceBundle(bundle);
              LOGGER.info("Loaded latest ServiceBundle for {} epoch {}", ServiceId, keyEpoch);
            } catch (Exception e) {
              LOGGER.error("Failed to load ServiceBundle into keyCache: {}", e.getMessage(), e);
            }
          }
        })
        .onFailure(err -> {
          LOGGER.warn("ServiceBundle for epoch {} not found, attempting to find latest", keyEpoch);
          // Attempt to find latest available bundle and load it
          authControllerAccess.listServiceBundleEpochs(ServiceId)
            .onSuccess( epochs -> {
              if (epochs == null || epochs.isEmpty()) {
                LOGGER.warn("No service bundle epochs found in Vault for {}", ServiceId);
                return;
              }
              // find max epoch numeric
              long maxEpoch = epochs.stream().mapToLong(Long::parseLong).max().orElse(keyEpoch);
              authControllerAccess.getServiceBundle(ServiceId, maxEpoch)
                .onSuccess( latestBundle -> {
                  try {
                    if (latestBundle != null) {
                      keyCache.loadFromServiceBundle(latestBundle);
                      LOGGER.info("Loaded latest ServiceBundle for {} epoch {}", ServiceId, maxEpoch);
                    }
                  } catch (Exception e) {
                    LOGGER.error("Failed to load latest ServiceBundle: {}", e.getMessage(), e);
                  }
                })
                .onFailure(e -> LOGGER.warn("Failed to fetch latest ServiceBundle: {}", e.getMessage()));
            })
            .onFailure(e -> LOGGER.warn("Failed to list ServiceBundle epochs: {}", e.getMessage()));
        });

    }
    catch( Exception e )
    {
      LOGGER.error("Unexpected error in TLS exception handler: {}", e.getMessage(), e);
    }
  }

  private String computeHash(String content) throws Exception
  {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(content.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(hash);
  }

  private String shortHash(String h) 
  {
    if (h == null) return "none";
    return h.length() > 8 ? h.substring(0,8) : h;
  } 
  
  private void validateAttributes()
  {
    if( nameSpace == null || nameSpace.isEmpty() )
      throw new IllegalArgumentException( "Could not obtain namespace" );

    if( podName == null || podName.isEmpty() )
      throw new IllegalArgumentException( "POD_NAME environment variable must be set" );

    if( authConfig == null )
      throw new IllegalStateException( "Failed to read authcontroller configuration" );
  }

  /**
   * Start the authcontroller service and initialize all components
   */
  public void start()
  {
    LOGGER.info( "Starting AuthController Service..." );

    try
    {
      deployPrerequisiteServices();
    } 
    catch( Exception e )
    {
      String errMsg = "Fatal error initializing AuthControllerServiceMain: " + e.getMessage();
      LOGGER.error( errMsg, e );
      cleanupResources();
      System.exit( 1 );
    }
  }

  /**
   * Stop the authcontroller service and cleanup resources
   */
  public void stop()
  {
    LOGGER.info( "Stopping AuthController Service..." );
    cleanupResources();
  }

  /**
   * Read configuration from ConfigMap
   */
  private AuthControllerConfig readConfig( KubernetesClient client, String nameSpace, String name )
  {
    LOGGER.info( "Reading configuration from configMap: {} in namespace: {}", name, nameSpace );

    ConfigMap config = client.configMaps().inNamespace( nameSpace ).withName( name ).get();

    if( config == null )
    {
      LOGGER.error( "ConfigMap not found: " + name );
      return null;
    }

    Map<String, String> configData = config.getData();
    authConfig = new AuthControllerConfig( configData );
    LOGGER.info( "Configuration read successfully" );

    return authConfig;
  }

  private String getPodName()
  {
    podName = System.getenv( "POD_NAME" );
    if( podName == null || podName.isEmpty() )
    {
      LOGGER.warn( "POD_NAME environment variable is not set" );
    }
    return podName;
  }

  /**
   * Cleanup all resources in proper order
   */
  private void cleanupResources()
  {
    LOGGER.info( "Starting cleanup of resources" );

    if (tlsExceptionConsumer != null)
    {
      try
      {
        tlsExceptionConsumer.unregister();
        LOGGER.info("Unregistered TLS exception handler");
      }
      catch (Exception e)
      {
        LOGGER.warn("Error unregistering TLS exception handler: {}", e.getMessage());
      }
    }
    
    workerExecutor.executeBlocking( () -> {
      try
      {
        // Undeploy all verticles in reverse order
        for( int i = deployedVerticles.size() - 1; i >= 0; i-- )
        {
          ChildVerticle child = deployedVerticles.get( i );
          String vertInfo = child.vertName() + " with id = " + child.id();

          try
          {
            LOGGER.info( "Undeploying verticle: {}", vertInfo );
            vertx.undeploy( child.id() ).toCompletionStage().toCompletableFuture().get( 10, TimeUnit.SECONDS );
            LOGGER.info( "Successfully undeployed verticle: {}", vertInfo );
          } 
          catch( Exception e )
          {
            LOGGER.warn( "Error while undeploying verticle {}: {}", vertInfo, e.getMessage(), e );
          }
        }

        deployedVerticles.clear();

        // Close Kubernetes client
        if( kubeClient != null )
        {
          try
          {
            kubeClient.close();
            LOGGER.info( "Kubernetes client closed" );
          } 
          catch( Exception e )
          {
            LOGGER.warn( "Error while closing Kubernetes client: {}", e.getMessage(), e );
          }
        }

        // Close Pulsar client
        if( natsTlsClient != null )
        {
          try
          {
            natsTlsClient.cleanup();
          } 
          catch( Exception e )
          {
            LOGGER.warn( "AuthControllerServiceMain.cleanupResources - Error closing pulsarClient. Error = " + e.getMessage() );
          }
        }

        // Close Vertx
        if( vertx != null )
        {
          try
          {
            vertx.close().toCompletionStage().toCompletableFuture().get( 10, TimeUnit.SECONDS );
            LOGGER.info( "Vertx instance closed" );
          } 
          catch( Exception e )
          {
            LOGGER.warn( "Error while closing Vertx instance: {}", e.getMessage(), e );
          }
        }
      } 
      catch( Exception e )
      {
        LOGGER.error( "Error encountered cleaning up resources. Error = " + e.getMessage() );
      }

      return ServiceCoreIF.SUCCESS;
    });

    System.exit( 1 );
  }

  /**
   * Deploy prerequisite services including key exchange and Pulsar components
   */
  private void deployPrerequisiteServices()
  {
    workerExecutor.executeBlocking( () -> 
    {
      try
      {
        // Deploy KeyExchangeVert
        DeploymentOptions options = new DeploymentOptions();
        options.setConfig( new JsonObject().put( "worker", true ) );

        String deploymentIdKeyExchange = vertx.deployVerticle( keyExchangeVert, options ).toCompletionStage().toCompletableFuture().get( 30, TimeUnit.SECONDS );
        deployedVerticles.add( new ChildVerticle( keyExchangeVert.getClass().getName(), deploymentIdKeyExchange ) );
        LOGGER.info( "KeyExchangeVert deployed successfully: {}", deploymentIdKeyExchange );

        // IMPORTANT: Offload blocking steps to a worker to avoid event-loop blocking
        waitForKeyExchangeComplete().onComplete( result -> 
        {
          if( result.succeeded() )
          {
            LOGGER.info( "Key exchange with metadata completed successfully" );
            workerExecutor.executeBlocking( () -> 
            {
              try
              {
                deployVaultApproleVerticles();
                deployAuthControllerVerticles();
              } 
              catch( Exception e )
              {
                LOGGER.error( "Error deploying AuthController verticles after key exchange: {}", e.getMessage(), e );
                // Cleanup here because we're on a worker
                cleanupResources();
              }
              return ServiceCoreIF.SUCCESS;
            } );
          } 
          else
          {
            LOGGER.error( "Key exchange failed: {}", result.cause().getMessage() );
            cleanupResources();
          }
        });
      }
      catch( Exception e )
      {
        LOGGER.error( "Error during prerequisites: {}", e.getMessage(), e );
        cleanupResources();
      }

      return ServiceCoreIF.SUCCESS;
    } );
  }

  /**
   * Wait for key exchange to complete before proceeding
   */
  private Future<String> waitForKeyExchangeComplete()
  {
    Promise<String> promise = Promise.promise();

    MessageConsumer<byte[]> consumer = vertx.eventBus().consumer( "metadata.keyExchange.complete", message -> 
    {
      String result = new String( message.body(), StandardCharsets.UTF_8 );
      if( ServiceCoreIF.SUCCESS.equals( result ) )
      {
        promise.complete( result );
      }
      else
      {
        promise.fail( "Key exchange failed: " + result );
      }
    });

    // Set timeout
    vertx.setTimer( 30000, id -> 
    {
      if( !promise.future().isComplete() )
      {
        promise.fail( "Timeout waiting for key exchange" );
      }
    });

    // Cleanup on completion
    promise.future().onComplete( ar -> consumer.unregister() );

    return promise.future();
  }

  /**
   * Deploy verticles including Vault authentication
   */
  private void deployVaultApproleVerticles() throws Exception
  {
    DeploymentOptions options = new DeploymentOptions();
    options.setConfig( new JsonObject().put( "worker", true ) );

    try
    {
      // Deploy Vault AppRole Secret rotation for AuthController
      authControllerAccess = new VaultAccessHandler( vertx, authConfig.getServiceId(), authConfig.getAuthControllerAgentAddr(), authConfig.getBaoAgentHost(), Integer.parseInt( authConfig.getAuthControllerAgentPort() ), authConfig.getAuthControllerAgentTokenPath() );

      // Deploy Vault AppRole Secret rotation for AuthController
      authControllerAppRoleVert = new VaultAppRoleSecretRotationVert( kubeClient, nameSpace, authConfig.getAuthControllerAppRoleSecretName(), authConfig.getAuthControllerAppRoleName(), Long.parseLong( authConfig.getSecretIDRotationMs() ),
          authControllerAccess );

      String deploymentIdAuthController = vertx.deployVerticle( authControllerAppRoleVert, options ).toCompletionStage().toCompletableFuture().get( 60, TimeUnit.SECONDS );
      deployedVerticles.add( new ChildVerticle( authControllerAppRoleVert.getClass().getName(), deploymentIdAuthController ) );
      LOGGER.info( "VaultAppRoleSecretRotationVert for authcontroller-vault-approle deployed successfully: {}", deploymentIdAuthController );

    } 
    catch( Exception e )
    {
      LOGGER.error( "Fatal error deploying Pulsar verticles: {}", e.getMessage(), e );
      throw e;
    }

    LOGGER.info( "AuthControllerServiceMain.deployPulsarVerticles() - Pulsar verticles deployed successfully" );
  }

  /**
   * Deploy AuthController-specific verticles for request handling
   */
  private void deployAuthControllerVerticles() throws Exception
  {
    DeploymentOptions authControllerOptions = new DeploymentOptions();
    authControllerOptions.setConfig( new JsonObject().put( "worker", true ) );

    workerExecutor.executeBlocking( () -> 
    {
      LOGGER.info( "AuthControllerServiceMain.deployAuthControllerVerticles - Start inside workerExecutor" );
      try
      {
        // Deploy Producer Verticle
        producerVert = new AuthControllerProducerVert( natsTlsClient, signedMsgProcessor, authConfig );
        String producerDeploymentId = vertx.deployVerticle( producerVert, authControllerOptions ).toCompletionStage().toCompletableFuture().get( 30, TimeUnit.SECONDS );
        deployedVerticles.add( new ChildVerticle( producerVert.getClass().getName(), producerDeploymentId ) );
        LOGGER.info( "AuthControllerProducerVert deployed successfully: {}", producerDeploymentId );

        // Deploy Consumer Verticle
        consumerVert = new AuthControllerConsumerVert( natsTlsClient, signedMsgProcessor, authConfig );
        String consumerDeploymentId = vertx.deployVerticle( consumerVert, authControllerOptions ).toCompletionStage().toCompletableFuture().get( 30, TimeUnit.SECONDS );
        deployedVerticles.add( new ChildVerticle( consumerVert.getClass().getName(), consumerDeploymentId ) );
        LOGGER.info( "AuthControllerConsumerVert deployed successfully: {}", consumerDeploymentId );

        // Deploy CABundleUpdateVert
        String deploymentIdCABundle = vertx.deployVerticle( caBundleUpdateVert, authControllerOptions ).toCompletionStage().toCompletableFuture().get( 30, TimeUnit.SECONDS );
        deployedVerticles.add( new ChildVerticle( caBundleUpdateVert.getClass().getName(), deploymentIdCABundle ) );
        LOGGER.info( "CABundleUpdateVert deployed successfully: {}", deploymentIdCABundle );
      } 
      catch( Exception e )
      {
        LOGGER.error( "Fatal error deploying AuthController verticles: {}", e.getMessage(), e );
        throw e;
      }

      LOGGER.info( "AuthControllerServiceMain.deployAuthControllerVerticles() - All AuthController verticles deployed successfully" );
      return ServiceCoreIF.SUCCESS;
    } );
  }

  public KubernetesClient getKubernetesClient()
  {
    return kubeClient;
  }

  public static void main( String[] args )
  {
    LOGGER.info( "AuthControllerServiceMain.main - Starting AuthController Service" );

    final AuthControllerServiceMain authControllerSvc = new AuthControllerServiceMain();

    // Register shutdown hook for graceful shutdown
    Runtime.getRuntime().addShutdownHook( new Thread( () -> 
    {
      LOGGER.info( "Shutdown hook triggered - cleaning up resources" );
      authControllerSvc.cleanupResources();
    }) );

    authControllerSvc.start();
  }
}