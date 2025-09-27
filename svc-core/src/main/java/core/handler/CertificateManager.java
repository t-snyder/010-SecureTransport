package core.handler;


import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.Watch;
import io.fabric8.kubernetes.client.Watcher;
import io.fabric8.kubernetes.client.WatcherException;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.util.Base64;
import java.util.EnumSet;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import core.pulsar.PulsarTLSClient;

/**
 * Manages client certificates for Pulsar authentication using cert-manager
 */
public class CertificateManager
{
  private static final Logger LOGGER = LoggerFactory.getLogger( CertificateManager.class );

  private static final String ClientPath = "/app/certs/client";
  
  private final KubernetesClient kubeClient;
  private final String namespace;
  private final String clientCertSecretName;
  private final String certPath;
  private final String keyPath;
  private final String caCertPath;
  private final String clientCertPath;
  
  private final CertificateUpdateCallbackIF updateCallback; // Interface instead of concrete class
  private CompletableFuture<Void>           certReadyFuture = new CompletableFuture<>();

  private Watch certWatcher;

  
  public CertificateManager( KubernetesClient kubeClient, String namespace, String clientCertSecretName, 
                             String caPath, String certPath, CertificateUpdateCallbackIF updateCallback )
  {
    this.kubeClient = kubeClient;
    this.namespace = namespace;
    this.clientCertSecretName = clientCertSecretName;
    this.certPath             = certPath + "tls.crt";
    this.keyPath              = certPath + "tls.key";
    this.caCertPath           = caPath;
    this.clientCertPath       = ClientPath;
    this.updateCallback       = updateCallback;
       
    LOGGER.info( "======================================================================" );
    LOGGER.info( "CertificateManager constructor - clientCertSecretName = " + clientCertSecretName  );
    LOGGER.info( "CertificateManager constructor - certPath = " + this.certPath  );
    LOGGER.info( "CertificateManager constructor - keyPath = " + keyPath  );
    LOGGER.info( "CertificateManager constructor - caCertPath = " + caCertPath  );
    LOGGER.info( "CertificateManager constructor - clientCertPath = " + clientCertPath  );
    LOGGER.info( "======================================================================" );

  }

  /**
   * Initialize certificate management and watch for updates
   */
  public CompletableFuture<Void> initialize()
  {
    try
    {
      LOGGER.info( "CertificateManager.initialize -certPath = " + certPath );
      
      // Create certificate directory if it doesn't exist
      Path certDir = Paths.get( clientCertPath );
      if( !Files.exists( certDir ))
      {
        Files.createDirectories( certDir );
      }

      // Load initial certificates
      loadCertificate();

      // Start watching for certificate updates
      watchCertificateSecret();

      return certReadyFuture;
    } 
    catch( Exception e )
    {
      LOGGER.error( "Failed to initialize certificate manager", e );
      certReadyFuture.completeExceptionally( e );
      return certReadyFuture;
    }
  }

  /**
   * Load certificate from Kubernetes secret and write to filesystem
   */
  private void loadCertificate() throws Exception
  {
    Secret  certSecret          = kubeClient.secrets().inNamespace( namespace ).withName( clientCertSecretName ).get();
    boolean certificatesUpdated = false;

    LOGGER.info( "CertManager.loadCertificate() - clientCertPath = " + clientCertPath );
    if( certSecret == null )
    {
      throw new RuntimeException( "Client certificate secret not found: " + clientCertSecretName );
    }

    Map<String, String> data = certSecret.getData();
    if( data == null )
    {
      throw new RuntimeException( "Certificate secret has no data" );
    }

    // Write certificate files if exists
    if( data.containsKey( "tls.crt" ))
    {
      writeCertificateFile( data.get( "tls.crt" ), clientCertPath + "/tls.crt" );
      certificatesUpdated = true;
    }
    
    if( data.containsKey( "tls.key" ))
    {
      writeCertificateFile( data.get( "tls.key" ), clientCertPath + "/tls.key" );
      certificatesUpdated = true;
    }
 
    // Validate certificates after writing
    if( certificatesUpdated ) 
    {
      validateCertificate( clientCertPath + "/tls.crt" );
    }

    LOGGER.info( "Client certificates loaded successfully" );

    if( !certReadyFuture.isDone() )
    {
      certReadyFuture.complete( null );
    }
  }

  /**
   * Write base64 encoded certificate data to file
   */
  private void writeCertificateFile( String base64Data, String filePath ) 
   throws IOException
  {
    if( base64Data == null )
    {
      throw new IOException( "Certificate data is null for path: " + filePath );
    }

    byte[] decodedData = Base64.getDecoder().decode(base64Data);
    Path   tempFile    = Paths.get( filePath + ".tmp" );
    Path   finalFile   = Paths.get (filePath );
    
    // Write to temporary file first
    Files.write(tempFile, decodedData );
    
    // Set restrictive permissions (owner read/write only)
    try 
    {
      Files.setPosixFilePermissions( tempFile, EnumSet.of( PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE ));
    } 
    catch( UnsupportedOperationException e ) 
    {
      // POSIX permissions not supported on this filesystem (e.g., Windows)
      LOGGER.debug("POSIX file permissions not supported, skipping permission setting");
    }
    
    // Atomic move to final location
    Files.move( tempFile, finalFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING );

    LOGGER.info("Written certificate file atomically: {}", filePath);
  }

  /**
   * Validate certificate
   */
  private void validateCertificate( String certPath )
    throws Exception 
  {
    if( !Files.exists( Paths.get( certPath ))) 
    {
      throw new RuntimeException("Certificate file not found: " + certPath);
    }

    byte[]             certBytes = Files.readAllBytes(Paths.get( certPath ));
    CertificateFactory cf        = CertificateFactory.getInstance( "X.509" );
    X509Certificate    cert      = (X509Certificate) cf.generateCertificate( new ByteArrayInputStream( certBytes ));
      
    // Check if certificate is expired
    cert.checkValidity();
      
    // Check if certificate is expiring soon (e.g., within 7 days)
    long daysUntilExpiry = ( cert.getNotAfter().getTime() - System.currentTimeMillis() ) / (24 * 60 * 60 * 1000 );
    if( daysUntilExpiry <= 7 ) 
    {
      LOGGER.warn("Certificate expires in {} days", daysUntilExpiry);
    } 
    else 
    {
      LOGGER.info("Certificate is valid for {} days", daysUntilExpiry);
    }
  }
 
  /**
   * Watch for certificate secret changes
   */
  private void watchCertificateSecret()
  {
    certWatcher = kubeClient.secrets().inNamespace( namespace ).withName( clientCertSecretName ).watch( new Watcher<Secret>()
    {
      @Override
      public void eventReceived( Action action, Secret secret )
      {
        LOGGER.info( "Certificate secret {} event: {}", clientCertSecretName, action );

        if( action == Action.MODIFIED || action == Action.ADDED )
        {
          try
          {
            loadCertificate();
            LOGGER.info( "Certificate reloaded successfully" );

            // Directly call the Pulsar client method
            // Use interface callback instead of direct client reference
            if( updateCallback != null ) 
            {
              updateCallback.onCertificateUpdated();
            }
          } 
          catch( Exception e )
          {
            LOGGER.error( "Failed to reload certificate", e );

            // Use interface callback instead of direct client reference
            if( updateCallback != null ) 
            {
              updateCallback.onCertificateUpdateFailed(e);
            }
          }
        }
      }

      @Override
      public void onClose( WatcherException cause )
      {
        if( certWatcher != null )
          certWatcher.close();
        
        if( cause != null )
        {
          LOGGER.error( "Certificate watcher closed due to exception", cause );
        } 
        else
        {
          LOGGER.info( "Certificate watcher closed" );
        }
      }
    } );
  }

  /**
   * Check if certificates are healthy and valid
   */
  public boolean isCertificateHealthy() 
  {
    try 
    {
      Path certFile = Paths.get(clientCertPath + "/tls.crt");
      Path keyFile  = Paths.get(clientCertPath + "/tls.key");
          
      if( !Files.exists( certFile ) || !Files.exists( keyFile )) 
      {
        return false;
      }
          
      // Check certificate validity
      validateCertificate(certFile.toString());
      return true;
    } 
    catch( Exception e ) 
    {
      LOGGER.warn("Certificate health check failed", e);
      return false;
    }
  }

  public long getCertificateExpirationTime() throws Exception
  {
    // Wait for certificates to be ready
    certReadyFuture.get();

    String certFilePath = clientCertPath + "/tls.crt";
    if( !Files.exists( Paths.get( certFilePath ) ) )
    {
      throw new RuntimeException( "Certificate file not found: " + certFilePath );
    }

    byte[] certBytes = Files.readAllBytes( Paths.get( certFilePath ) );
    CertificateFactory cf = CertificateFactory.getInstance( "X.509" );
    X509Certificate cert = (X509Certificate)cf.generateCertificate( new ByteArrayInputStream( certBytes ) );

    return cert.getNotAfter().getTime();
  }
  
  public String getCertPath()
  {
    return new String( clientCertPath + "/tls.crt" );
  }

  public String getKeyPath()
  {
    return new String( clientCertPath + "/tls.key" );
  }

  public String getCaCertPath()
  {
    return caCertPath;
  }

  public void close()
  {
    if( certWatcher != null )
    {
      certWatcher.close();
      certWatcher = null;
    }
  }
}
