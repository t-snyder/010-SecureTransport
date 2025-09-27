package core.handler;


import io.fabric8.kubernetes.api.model.apps.Deployment;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.model.ServiceCoreIF;

/**
 * Handles certificate rotation and rolling updates of deployments
 */
public class CertificateRotationService
{
  private static final Logger LOGGER = LoggerFactory.getLogger( CertificateRotationService.class );

  private final KubernetesClient kubeClient;
//  private final Vertx vertx;
  private final String namespace;

  private WorkerExecutor workerExecutor = null;

  public CertificateRotationService( KubernetesClient kubeClient, Vertx vertx, String namespace )
  {
    this.kubeClient = kubeClient;
//    this.vertx = vertx;
    this.namespace = namespace;
    
    workerExecutor = vertx.createSharedWorkerExecutor( "cert-rotation", 2 );
  }

  public void triggerRollingUpdate( String deploymentName ) 
  {
    workerExecutor.executeBlocking( () -> 
    {
      try 
      {
        Deployment deployment = kubeClient.apps().deployments()
                                                .inNamespace( namespace )
                                                .withName( deploymentName )
                                                .get();

        if( deployment == null ) 
        {
          throw new RuntimeException("Deployment not found: " + deploymentName);
        }

        // Add annotation to trigger rolling update
        Map<String, String> annotations = deployment.getSpec().getTemplate().getMetadata().getAnnotations();
        if( annotations == null ) 
        {
          annotations = new HashMap<>();
        }

        annotations.put("cert.rotation/timestamp", String.valueOf(System.currentTimeMillis()));
        deployment.getSpec().getTemplate().getMetadata().setAnnotations(annotations);

        // Apply the modified deployment using serverSideApply
        kubeClient.resource(deployment).serverSideApply();

        LOGGER.info("Rolling update triggered for deployment: {}", deploymentName);
      } 
      catch( Exception e ) 
      {
        LOGGER.error("Failed to trigger rolling update for deployment: " + deploymentName, e);
      }

      return ServiceCoreIF.SUCCESS;
    });
  }
  /**
   * Check if certificate rotation is needed based on expiration time
   */
  public boolean isRotationNeeded( long expirationTime )
  {
    long now = System.currentTimeMillis();
    long daysUntilExpiry = ( expirationTime - now ) / ( 24 * 60 * 60 * 1000 );

    // Rotate if certificate expires within 30 days
    return daysUntilExpiry <= 30;
  }
}