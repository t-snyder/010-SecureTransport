package service;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.file.FileSystemOptions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import core.nats.NatsTLSClient;
import core.model.ChildVerticle;
import core.utils.ConfigReader;
import helper.MetadataConfig;
import verticle.MetadataServiceVert;

public class MetadataService
{
  private static final Logger LOGGER      = LoggerFactory.getLogger( MetadataService.class );
  private static final String ConfEnvKey  = "CONFIG_MAP_NAME"; 
  private static final String DefaultConf = "metadata-svc-config";
  private static ConfigReader confReader  = new ConfigReader();

  private Vertx               vertx          = null;
  private KubernetesClient    kubeClient     = null;
  private String              nameSpace      = null;
  private String              configName     = null;
  private Map<String, String> config         = null;
  private MetadataConfig      metadataConfig = null;

  private NatsTLSClient       natsTLSClient     = null;
  private List<ChildVerticle> deployedVerticles = new ArrayList<ChildVerticle>();
  private WorkerExecutor      workerExecutor    = null;

  private MetadataServiceVert mdVert     = null;

  
  // Static inner helper class responsible for holding the Singleton instance
  private static class SingletonHelper 
  {
    // The Singleton instance is created when the class is loaded
    private static final MetadataService INSTANCE = new MetadataService();
  }

  // Global access point to get the Singleton instance
  public static MetadataService getInstance()
  {
    return SingletonHelper.INSTANCE;
  }

  private MetadataService()
  {
  }
 
  public void init( Vertx vertx )
   throws Exception
  {
    this.vertx = vertx;
 
    this.kubeClient = confReader.getKubeClient();
    this.nameSpace  = confReader.getNamespace();
    this.configName = confReader.getConfigMapNameFromEnv( ConfEnvKey );
    
    if( configName == null )
      configName = DefaultConf;
    
    LOGGER.info( "*** Namespace = " + nameSpace + "; Config map name = " + configName );
    
    this.config = confReader.getConfigProperties( configName );
 
    String metadataConfigJson = this.config.get( "metadataConfig.json" );
    if( metadataConfigJson == null ) 
    {
      throw new Exception("metadataConfig.json not found in config map");
    }

    ObjectMapper mapper = new ObjectMapper();
    this.metadataConfig = mapper.readValue( metadataConfigJson, MetadataConfig.class );

    verifyConfig(); 
    
    if( config == null )
    {
      String msg = "Could not obtain configuration map.";
      LOGGER.error( msg );
      throw new Exception( msg );
    }

    workerExecutor = vertx.createSharedWorkerExecutor("reconnect");
 
    initializeNatsClient();
    initMainVerticle();
    
    LOGGER.info("MetadataService initialization completed successfully");
  }

  private void initializeNatsClient()
    throws Exception 
  {
    try 
    {
      LOGGER.info("MetadataService.initializeNatsClient() - Initializing NATS TLS client...");

      Map<String, String> natsConfig = new HashMap<String, String>();
      natsConfig.put( NatsTLSClient.NATS_URLS,              metadataConfig.getNats().getNatsUrl()        );
      natsConfig.put( NatsTLSClient.NATS_CA_CERT_PATH,      metadataConfig.getNats().getNatsCaCertFile()     );
      natsConfig.put( NatsTLSClient.NATS_CLIENT_CERT_PATH,  metadataConfig.getNats().getNatsClientCertPath() );
      natsConfig.put( NatsTLSClient.NATS_CLIENT_SECRET,     metadataConfig.getNats().getNatsCredentialsFile() );
      
      natsTLSClient = new NatsTLSClient( vertx, natsConfig, kubeClient, metadataConfig.getServiceId(), nameSpace );
        
      LOGGER.info("NATS TLS client initialized successfully");
    } 
    catch( Exception e ) 
    {
      String msg = "Failed to initialize NATS TLS client: " + e.getMessage();
      LOGGER.error(msg, e);
      cleanupResources();
      throw new RuntimeException(msg, e);
    }
  }
  
  private void initMainVerticle() 
    throws Exception 
  {
    try 
    {
      mdVert = new MetadataServiceVert( vertx, this, kubeClient, metadataConfig, nameSpace, natsTLSClient );
    }
    catch( Exception e ) 
    {
      String msg = "Fatal error creating MetadataServiceVert - system will stop: " + e.getMessage();
      LOGGER.error(msg, e);
      cleanupResources();
      throw new RuntimeException(msg, e);
    }
    
    try 
    {
      String mdVertId = vertx.deployVerticle( mdVert )
                             .toCompletionStage()
                             .toCompletableFuture().get();
 
      deployedVerticles.add( new ChildVerticle( mdVert.getClass().getName(), mdVertId ));
      LOGGER.info( "MetadataServiceVert deployment id is: " + mdVertId );
    } 
    catch( Exception e ) 
    {
      String msg = "Fatal initialization error in MetadataService: " + e.getMessage();
      LOGGER.error(msg, e);
      cleanupResources();
      throw new RuntimeException(msg, e);
    }
  }

  public List<ChildVerticle> getDeployedVerticles() 
  {
    return deployedVerticles;
  }
  
  private void verifyConfig()
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
  }

  public void cleanupResources() 
  {
    LOGGER.info("Starting cleanup of MetadataServiceVert resources");
    
    // First undeploy all verticles
    if( !deployedVerticles.isEmpty() && vertx != null ) 
    {
      for( ChildVerticle child : deployedVerticles ) 
      {
        String vertInfo = new String( child.vertName() + " with id = " + child.id() );
  
        try 
        {
          vertx.undeploy( child.id() ).toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
          LOGGER.info(" Successfully undeployed child verticle: " + vertInfo );
        } 
        catch( Exception e ) 
        {
          LOGGER.warn("Error while undeploying child verticle " + vertInfo + ": " + e.getMessage(), e);
        }
      }  
    }
    deployedVerticles.clear();

    // Cleanup NATS client
    if( natsTLSClient != null ) 
    {
      try 
      {
        natsTLSClient.cleanup();
        LOGGER.info("NATS TLS client cleanup completed");
      } 
      catch( Exception e ) 
      {
        LOGGER.warn("Error while cleaning up NATS client: " + e.getMessage(), e);
      }
    }
  
    if( kubeClient != null ) 
    {
      try 
      {
        kubeClient.close();
      } 
      catch( Exception e ) 
      {
        LOGGER.warn("Error while closing kubeClient: " + e.getMessage(), e);
      }
    }
    
    // Finally, close the Vertx instance
    if( vertx != null )
    {
      try 
      {
        vertx.close().toCompletionStage().toCompletableFuture().get();
        LOGGER.info("Closed Vertx instance");
      } 
      catch( Exception e ) 
      {
        LOGGER.warn( "Error while closing Vertx instance: " + e.getMessage(), e );
      }
    }
  }  

  // Main method can be used to run without Maven plugin
  public static void main( String[] args )
  {
    // Configure Vert.x to use a writable cache directory
    String cacheDir = System.getProperty( "vertx.cacheDirBase", "/app/data/vertx-cache");
    System.setProperty( "vertx.cacheDirBase", cacheDir);
    
    // Create Vert.x options with file system configuration
    VertxOptions options = new VertxOptions().setWorkerPoolSize( 20 )
                                             .setEventLoopPoolSize( 4 )
                                             .setFileSystemOptions( new FileSystemOptions().setFileCachingEnabled(true)
                                                                                           .setClassPathResolvingEnabled(false)
                                                                  );
    Vertx vertx = Vertx.vertx( options );

    MetadataService svc = MetadataService.getInstance();

    try
    {
      svc.init( vertx );
    } 
    catch( Exception e )
    {
      String msg = "Fatal error in MetadataService: " + e.getMessage();
      LOGGER.error( msg, e );
      svc.cleanupResources();
      vertx.close();
      System.exit( 1 );
    }
    
    // Register shutdown hook for graceful shutdown
    Runtime.getRuntime().addShutdownHook( new Thread(() -> 
    {
      LOGGER.info( "Shutdown hook triggered - cleaning up resources" );
      svc.cleanupResources();
    }));

  }
}
