package core.verticle;


import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.client.KubernetesClient;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;

import java.io.IOException;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.VaultAccessHandler;
import core.model.ServiceCoreIF;
import core.utils.B64Handler;

/**
 * This verticle rotates the 'secret-id' for a OpenBao AppRole by updating
 * the appropriate Kubernetes Secret. It requests a new secret-id from OpenBao
 * at startup and on a periodic interval, patches the K8s Secret, and works
 * seamlessly with Vault Agent that reads secret-id from a mounted file.
 */
public class VaultAppRoleSecretRotationVert extends AbstractVerticle
{
  private static final Logger LOGGER     = LoggerFactory.getLogger( VaultAppRoleSecretRotationVert.class );

  private final KubernetesClient kubeClient;
  private final String namespace;
  private final String secretName;
  private final String vaultRoleName;
  private final long   rotationIntervalMs;

  private VaultAccessHandler vaultAccessHandler = null;
  private WorkerExecutor     workerExecutor     = null;

  /**
   * Constructor with default tokenPath
   * 
   * @param kubeClient
   * @param namespace
   * @param secretName
   * @param vaultRoleName
   * @param vaultAgentHost
   * @param vaultAgentPort
   * @param rotationIntervalMs
   * @throws IOException
  */
  public VaultAppRoleSecretRotationVert( KubernetesClient kubeClient, 
                                         String namespace, 
                                         String secretName, 
                                         String vaultRoleName, 
                                         long   rotationIntervalMs,
                                         VaultAccessHandler vaultAccessHandler ) 
    throws IOException
  {
    this.kubeClient         = kubeClient;
    this.namespace          = namespace;
    this.secretName         = secretName;
    this.vaultRoleName      = vaultRoleName;
    this.rotationIntervalMs = rotationIntervalMs;

    this.vaultAccessHandler = vaultAccessHandler;  
  }

  @Override
  public void start( Promise<Void> startPromise )
  {
    LOGGER.info( "VaultAppRoleSecretRotationVerticle started for secret - " + secretName + "; with vault role name = " + vaultRoleName );
 
//    this.webClient      = WebClient.create(vertx);
    this.workerExecutor = vertx.createSharedWorkerExecutor( "approle-worker", 2, 360000 );

    // Generate new secret-id and update the K8s Secret at startup
    rotateSecretIdAsync();

    vertx.setPeriodic( rotationIntervalMs, id -> rotateSecretIdAsync());

    startPromise.complete();
  }

  /**
   * Asynchronously rotates the secret-id:
   * 1. Reads current role-id from K8s Secret.
   * 2. Requests new secret-id from Vault Agent API.
   * 3. Patches the K8s Secret with new secret-id.
   */
    private void rotateSecretIdAsync()
  {
    LOGGER.info( "Checking for secret_id update for role: {}", vaultRoleName );

    workerExecutor.executeBlocking( () -> 
    {
      try
      {
        // 1. Get current role_id from the Secret
        Secret k8sSecret = kubeClient.secrets().inNamespace(namespace).withName(secretName).get();
        if( k8sSecret == null || k8sSecret.getData() == null ) 
        {
          String errMsg = "VaultAppRoleSecretVert- rotateSecretIdAsync - Kubernetes Secret - " + secretName + " not found in namespace - " + namespace;
          LOGGER.error( errMsg );
          throw new Exception( errMsg );
        }
    
        String roleId = B64Handler.decodeB64( k8sSecret.getData().get( "role-id" ));
        if( roleId == null ) 
        {
          String errMsg = "VaultAppRoleSecretVert- rotateSecretIdAsync - role-id not found in K8s Secret - " + secretName;
          LOGGER.error( errMsg );
          throw new Exception( errMsg );
        }
 
        // 2. Get Vault token using handler
        Future<String> tokenFuture = vaultAccessHandler.getVaultToken();
        tokenFuture.onSuccess( token -> 
        {
          // 3. Request new secret-id via handler
          vaultAccessHandler.requestNewSecretId( vaultRoleName, token )
                            .onSuccess( newSecretId -> 
                             {
                               if( newSecretId != null ) 
                               {
                                 updateK8sSecretWithNewSecretId(k8sSecret, newSecretId);
                               }
                               else 
                               {
                                 LOGGER.error("Received null secret-id from Vault for role {}", vaultRoleName);
                               }
                             })
                            .onFailure( e -> 
                            {
                              LOGGER.error("Failed to rotate secret-id: {}", e.getMessage(), e);
                            });
        }).onFailure( err -> 
           {
             LOGGER.error("Failed to get Vault token: {}", err.getMessage(), err);
           });
      } 
      catch( Exception e ) 
      {
        String errMsg = "VaultAppRoleSecretRotationVert- rotateSecretIdAsync - error = " + e.getMessage();
        LOGGER.error(errMsg);
        return ServiceCoreIF.FAILURE;
      }

      return ServiceCoreIF.SUCCESS;
    });
  }

  
  /**
   * Updates the K8s Secret with the new base64-encoded secret-id.
   */
  private void updateK8sSecretWithNewSecretId( Secret k8sSecret, String newSecretId ) 
  {
    try 
    {
      Map<String, String> data = k8sSecret.getData();
      data.put("secret-id", B64Handler.encodeB64( newSecretId));

      kubeClient.secrets().inNamespace( namespace)
                          .withName( secretName )
                          .edit( s -> 
                           {
                             s.setData(data);
                             return s;
                           });
      LOGGER.info("Updated secret_id for role {} in Secret {}", vaultRoleName, secretName);
    } 
    catch( Exception e ) 
    {
      String errMsg = "VaultAppRoleSecretVert- updateK8sSecretWithNewSecretId - Failed to update K8s Secret: " + secretName + "; Error = " + e.getMessage();
      LOGGER.error( errMsg );
    }
  }
}