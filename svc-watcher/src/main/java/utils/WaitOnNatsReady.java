package utils;

import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.PodCondition;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.util.concurrent.TimeUnit;

public class WaitOnNatsReady
{
  private static KubernetesClient kubernetesClient = null;

  public static boolean waitOnNats( KubernetesClient client, String nameSpace, String podName )
  {
    kubernetesClient = client;

    Pod pod = kubernetesClient.pods().inNamespace( nameSpace )
                                     .withName(    podName   )
                                     .waitUntilCondition( p -> isPodReady( p ), 5, TimeUnit.MINUTES );

    if( pod != null && isPodReady( pod ) )
    {
      System.out.println( "NATS Pod is ready!" );
      return true;
    }
    else
    {
      System.out.println( "NATS Pod is not ready after waiting." );
      return false;
    }
  }

  private static boolean isPodReady( Pod pod )
  {
    if( pod == null || pod.getStatus()  == null ) return false;
    if( pod.getStatus().getConditions() == null ) return false;

    for( PodCondition condition : pod.getStatus().getConditions() )
    {
      if( "Ready".equals( condition.getType() ) && "True".equalsIgnoreCase( condition.getStatus() ) )
      {
        return true;
      }
    }
    return false;
  }
}