package service;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
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

import utils.GatekeeperConfig;
import verticle.GatekeeperConsumerVert;
import verticle.AuthRequestGeneratorVert;

/**
 * Gatekeeper Service Main - now NATS-based (refactored from Pulsar).
 * Responsibilities: 1. Key exchange & CA bundle rotation 2. Sending auth
 * requests (load generator + HTTP API) 3. Consuming auth responses
 */
public class GatekeeperServiceMain
{

  private static final Logger LOGGER = LoggerFactory.getLogger( GatekeeperServiceMain.class );

  private static final String ServiceId = "gatekeeper";
  private static final String MetadataId = "metadata";

  private GatekeeperConfig gatekeeperConfig;
  private String nameSpace;
  private String podName;

  private Vertx vertx;
  private KubernetesClient kubeClient;
  private NatsTLSClient natsTlsClient;
  private KeySecretManager keyCache;
  private WorkerExecutor workerExecutor;

  private SignedMessageProcessor signedMsgProcessor;
  private VaultAccessHandler gatekeeperAccess;
  private KeyExchangeVert keyExchangeVert;
  private CABundleUpdateVert caBundleUpdateVert;
  private VaultAppRoleSecretRotationVert gatekeeperAppRoleVert;
  private GatekeeperConsumerVert consumerVert;
  private AuthRequestGeneratorVert requestGeneratorVert;

  private final List<ChildVerticle>   deployedVerticles    = new ArrayList<>();
  private MessageConsumer<JsonObject> tlsExceptionConsumer = null;

  
  public GatekeeperServiceMain()
  {
    try
    {
      VertxOptions options = new VertxOptions().setWorkerPoolSize( 32 ).setEventLoopPoolSize( 8 ).setMaxWorkerExecuteTime( 60000 );
      this.vertx = Vertx.vertx( options );

      Config apiConfig = new ConfigBuilder().build();
      kubeClient = new KubernetesClientBuilder().withConfig( apiConfig ).build();
      LOGGER.info( "GatekeeperServiceMain() - Kubernetes client initialized" );

      this.nameSpace = kubeClient.getNamespace();
      this.podName = resolvePodName();
      this.gatekeeperConfig = readConfig( kubeClient, nameSpace, "gatekeeper-config" );

      validateAttributes();

      // Build NATS config map (ensure GatekeeperConfig exposes these getters)
      Map<String, String> natsConfig = Map.of( 
          NatsTLSClient.NATS_URLS,             gatekeeperConfig.getNatsURL(), 
          NatsTLSClient.NATS_CA_CERT_PATH,     gatekeeperConfig.getCaCertPath(), 
          NatsTLSClient.NATS_CLIENT_CERT_PATH, gatekeeperConfig.getClientCertPath(),
          NatsTLSClient.NATS_CLIENT_SECRET,    gatekeeperConfig.getTlsSecret() );

      natsTlsClient = new NatsTLSClient( vertx, natsConfig, kubeClient, ServiceId, nameSpace );
      LOGGER.info( "GatekeeperServiceMain() - NatsTLSClient created" );

      gatekeeperAccess = new VaultAccessHandler( vertx, 
                                                 gatekeeperConfig.getServiceId(), 
                                                 gatekeeperConfig.getGatewayAgentAddr(), 
                                                 gatekeeperConfig.getBaoAgentHost(), 
                                                 Integer.parseInt( gatekeeperConfig.getGatewayAgentPort() ),
                                                 gatekeeperConfig.getGatewayAgentTokenPath() );

      keyCache = new KeySecretManager( vertx, gatekeeperAccess );

      // KeyExchangeVert (refactored signature similar to AuthController side)
      keyExchangeVert = new KeyExchangeVert( natsTlsClient, keyCache, ServiceId );

      // CA bundle updater now NATS aware
      caBundleUpdateVert = new CABundleUpdateVert( kubeClient, natsTlsClient, keyCache, ServiceId, nameSpace );

      workerExecutor = vertx.createSharedWorkerExecutor( "main", 
                                                         5,              // poolSize
                                                         60_000,         // maxExecuteTime in ms (60 seconds)
                                                         TimeUnit.MILLISECONDS
                                                       );

      signedMsgProcessor = new SignedMessageProcessor( workerExecutor, keyCache );
      
      registerTlsExceptionHandler();
      LOGGER.info("TLS exception handler registered on event bus");
    }
    catch( Exception e )
    {
      String errMsg = "Error initializing GatekeeperServiceMain: " + e.getMessage();
      LOGGER.error( errMsg, e );
      throw new RuntimeException( errMsg );
    }
  }

  private void validateAttributes()
  {
    if( nameSpace == null || nameSpace.isEmpty() )
      throw new IllegalArgumentException( "Could not obtain namespace" );
    if( podName == null || podName.isEmpty() )
      throw new IllegalArgumentException( "POD_NAME environment variable must be set" );
    if( gatekeeperConfig == null )
      throw new IllegalStateException( "Failed to read gatekeeper configuration" );
  }

  public void start()
  {
    LOGGER.info( "Starting Gatekeeper Service (NATS)..." );
    try
    {
      deployPrerequisites();
    }
    catch( Exception e )
    {
      LOGGER.error( "Fatal error initializing GatekeeperServiceMain: {}", e.getMessage(), e );
      cleanupAllAndExit();
    }
  }

  public void stop()
  {
    LOGGER.info( "Stopping Gatekeeper Service..." );
    cleanupAllAndExit();
  }

  private GatekeeperConfig readConfig( KubernetesClient client, String ns, String name )
  {
    LOGGER.info( "Reading configuration from ConfigMap: {} in namespace: {}", name, ns );
    ConfigMap cfg = client.configMaps().inNamespace( ns ).withName( name ).get();
    if( cfg == null )
    {
      LOGGER.error( "ConfigMap not found: {}", name );
      return null;
    }
    gatekeeperConfig = new GatekeeperConfig( cfg.getData() );
    LOGGER.info( "Configuration loaded." );
    return gatekeeperConfig;
  }

  private String resolvePodName()
  {
    String pn = System.getenv( "POD_NAME" );
    if( pn == null || pn.isEmpty() )
    {
      LOGGER.warn( "POD_NAME environment variable is not set" );
    }
    return pn;
  }

  private void registerTlsExceptionHandler()
  {
    tlsExceptionConsumer = vertx.eventBus().consumer("nats.tls.exception", msg -> 
    {
      try 
      {
        JsonObject body = (JsonObject) msg.body();
        LOGGER.warn("Received nats.tls.exception event: {}", body);

        // Offload heavy work to worker using explicit Promise type and handle completion
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
      // Compute current CA and key epochs
      core.utils.CAEpochUtil caEpochUtil = new core.utils.CAEpochUtil();
      long currentCaEpoch = caEpochUtil.epochNumberForInstant(java.time.Instant.now());
      long keyEpoch = core.utils.KeyEpochUtil.epochNumberForInstant(java.time.Instant.now());

      LOGGER.info("Handling TLS exception: computed currentCaEpoch={}, keyEpoch={}", currentCaEpoch, keyEpoch);

      // 1) Fetch current CA bundle from Vault and apply if different from what NATS client has applied
      gatekeeperAccess.getCurrentCaBundle("NATS")
        .onSuccess(caBundle -> {
          try {
            if (caBundle == null) {
              LOGGER.warn("No CA bundle returned from Vault for NATS");
              return;
            }

            String fetchedHash = computeHash(caBundle.getCaBundle());
            String appliedHash = natsTlsClient.getAppliedCaContentHash();

            if (appliedHash == null || !appliedHash.equals(fetchedHash)) {
              LOGGER.info("Applied CA hash differs from Vault CA (applied={}, vault={}) - applying update",
                          shortHash(appliedHash), shortHash(fetchedHash));

              // Apply CA bundle via NATS client (this triggers the client's rotation/recreate flow)
              natsTlsClient.handleCaBundleUpdate(caBundle).onComplete(ar -> {
                if (ar.succeeded()) {
                  LOGGER.info("Applied new CA bundle from Vault successfully");
                } else {
                  LOGGER.error("Failed to apply CA bundle from Vault: {}", ar.cause() != null ? ar.cause().getMessage() : "unknown", ar.cause());
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
          LOGGER.warn("Failed to retrieve CA bundle from Vault: {}", err.getMessage(), err);
        });

      // 2) Fetch the ServiceBundle for the current key epoch and load keys into key cache.
      //    If the exact epoch is not found, attempt to load the latest available bundle.
      gatekeeperAccess.getServiceBundle(ServiceId, keyEpoch)
        .onSuccess(bundle -> {
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
          LOGGER.warn("ServiceBundle for epoch {} not found, attempting to find latest: {}", keyEpoch, err.getMessage());

          gatekeeperAccess.listServiceBundleEpochs(ServiceId)
            .onSuccess(epochs -> {
              try {
                if (epochs == null || epochs.isEmpty()) {
                  LOGGER.warn("No service bundle epochs found in Vault for {}", ServiceId);
                  return;
                }

                long maxEpoch = epochs.stream()
                                      .mapToLong(Long::parseLong)
                                      .max()
                                      .orElse(keyEpoch);

                gatekeeperAccess.getServiceBundle(ServiceId, maxEpoch)
                  .onSuccess(latestBundle -> {
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
              } catch (Exception e) {
                LOGGER.warn("Failed to parse epoch list or load latest ServiceBundle: {}", e.getMessage(), e);
              }
            })
            .onFailure(e -> LOGGER.warn("Failed to list ServiceBundle epochs: {}", e.getMessage(), e));
        });
    }
    catch (Exception e)
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
  
  /**
   * Deploy prerequisites: monitoring (if any), key exchange, CA bundle updater,
   * then wait for key exchange.
   */
  private void deployPrerequisites()
  {
    workerExecutor.executeBlocking( () -> {
      try
      {
        DeploymentOptions opts = new DeploymentOptions().setConfig( new JsonObject().put( "worker", true ) );

        // Deploy KeyExchangeVert
        String keyExId = vertx.deployVerticle( keyExchangeVert, opts ).toCompletionStage().toCompletableFuture().get( 30, TimeUnit.SECONDS );
        deployedVerticles.add( new ChildVerticle( keyExchangeVert.getClass().getName(), keyExId ) );
        LOGGER.info( "KeyExchangeVert deployed: {}", keyExId );

        waitForKeyExchangeComplete().onComplete( ar -> {
          if( ar.succeeded() )
          {
            LOGGER.info( "Key exchange complete. Deploying Gatekeeper verticles..." );
            try
            {
              deployGatekeeperVerticles();
            }
            catch( Exception e )
            {
              LOGGER.error( "Error deploying Gatekeeper verticles: {}", e.getMessage(), e );
              cleanupAllAndExit();
            }
          }
          else
          {
            LOGGER.error( "Key exchange failed: {}", ar.cause().getMessage() );
            cleanupAllAndExit();
          }
        } );
      }
      catch( Exception e )
      {
        LOGGER.error( "Error during prerequisites: {}", e.getMessage(), e );
        cleanupAllAndExit();
      }
      return ServiceCoreIF.SUCCESS;
    } );
  }

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
    } );

    vertx.setTimer( 30000, id -> {
      if( !promise.future().isComplete() )
      {
        promise.fail( "Timeout waiting for key exchange" );
      }
    } );

    promise.future().onComplete( ar -> consumer.unregister() );
    return promise.future();
  }

  private void deployGatekeeperVerticles() throws Exception
  {
    DeploymentOptions opts = new DeploymentOptions().setConfig( new JsonObject().put( "worker", true ) );

    workerExecutor.executeBlocking( () -> {
      LOGGER.info( "Deploying Gatekeeper (NATS) verticles..." );
      try
      {
        // Vault AppRole rotation
        gatekeeperAccess = new VaultAccessHandler( vertx, gatekeeperConfig.getServiceId(), 
                                                          gatekeeperConfig.getGatewayAgentAddr(),
                                                          gatekeeperConfig.getBaoAgentHost(), 
                                                          Integer.parseInt( gatekeeperConfig.getGatewayAgentPort() ),
                                                          gatekeeperConfig.getGatewayAgentTokenPath() );
 
        gatekeeperAppRoleVert = new VaultAppRoleSecretRotationVert( kubeClient, nameSpace, 
                                                                    gatekeeperConfig.getGatewayAppRoleSecretName(),
                                                                    gatekeeperConfig.getGatewayAppRoleName(), 
                                                                    Long.parseLong( gatekeeperConfig.getSecretIDRotationMs() ),
                                                                    gatekeeperAccess );
        String vaultId = vertx.deployVerticle( gatekeeperAppRoleVert, opts ).toCompletionStage().toCompletableFuture().get( 60, TimeUnit.SECONDS );
        deployedVerticles.add( new ChildVerticle( gatekeeperAppRoleVert.getClass().getName(), vaultId ) );
        LOGGER.info( "VaultAppRoleSecretRotationVert deployed: {}", vaultId );

        // Deploy CA Bundle updater
        String caId = vertx.deployVerticle( caBundleUpdateVert, opts ).toCompletionStage().toCompletableFuture().get( 30, TimeUnit.SECONDS );
        deployedVerticles.add( new ChildVerticle( caBundleUpdateVert.getClass().getName(), caId ) );
        LOGGER.info( "CABundleUpdateVert deployed: {}", caId );

        
        // Consumer (auth responses)
        consumerVert = new GatekeeperConsumerVert( natsTlsClient, gatekeeperConfig, keyCache, signedMsgProcessor );
        String consId = vertx.deployVerticle( consumerVert, opts ).toCompletionStage().toCompletableFuture().get( 30, TimeUnit.SECONDS );
        deployedVerticles.add( new ChildVerticle( consumerVert.getClass().getName(), consId ) );
        LOGGER.info( "GatekeeperConsumerVert deployed: {}", consId );

        // Load / request generator
        requestGeneratorVert = new AuthRequestGeneratorVert( natsTlsClient, signedMsgProcessor, gatekeeperConfig );
        String genId = vertx.deployVerticle( requestGeneratorVert, opts ).toCompletionStage().toCompletableFuture().get( 30, TimeUnit.SECONDS );
        deployedVerticles.add( new ChildVerticle( requestGeneratorVert.getClass().getName(), genId ) );
        LOGGER.info( "AuthRequestGeneratorVert deployed: {}", genId );

      }
      catch( Exception e )
      {
        LOGGER.error( "Fatal error deploying Gatekeeper verticles: {}", e.getMessage(), e );
        throw new RuntimeException( e );
      }

      LOGGER.info( "All Gatekeeper verticles deployed successfully (NATS)." );
      return ServiceCoreIF.SUCCESS;
    } );
  }

  private void cleanupAllAndExit()
  {
    LOGGER.info( "Cleaning up Gatekeeper resources" );

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
        for( int i = deployedVerticles.size() - 1; i >= 0; i-- )
        {
          ChildVerticle child = deployedVerticles.get( i );
          try
          {
            vertx.undeploy( child.id() ).toCompletionStage().toCompletableFuture().get( 10, TimeUnit.SECONDS );
          }
          catch( Exception e )
          {
            LOGGER.warn( "Error undeploying verticle {}: {}", child.vertName(), e.getMessage() );
          }
        }
        deployedVerticles.clear();

        if( kubeClient != null )
        {
          try
          {
            kubeClient.close();
          }
          catch( Exception e )
          {
            LOGGER.warn( "Error closing Kubernetes client: {}", e.getMessage() );
          }
        }
        if( natsTlsClient != null )
        {
          try
          {
            natsTlsClient.cleanup();
          }
          catch( Exception e )
          {
            LOGGER.warn( "Error closing NATS client: {}", e.getMessage() );
          }
        }
        if( vertx != null )
        {
          try
          {
            vertx.close().toCompletionStage().toCompletableFuture().get( 10, TimeUnit.SECONDS );
          }
          catch( Exception e )
          {
            LOGGER.warn( "Error closing Vertx: {}", e.getMessage() );
          }
        }
      }
      catch( Exception e )
      {
        LOGGER.error( "Cleanup error: {}", e.getMessage() );
      }
      return ServiceCoreIF.SUCCESS;
    } );

    System.exit( 1 );
  }

  public KubernetesClient getKubernetesClient()
  {
    return kubeClient;
  }

  public static void main( String[] args )
  {
    LOGGER.info( "GatekeeperServiceMain.main - Starting Gatekeeper (NATS) Service" );
    final GatekeeperServiceMain svc = new GatekeeperServiceMain();

    Runtime.getRuntime().addShutdownHook( new Thread( () -> {
      LOGGER.info( "Shutdown hook triggered - cleaning up resources" );
      svc.cleanupAllAndExit();
    } ) );

    svc.start();
  }
}