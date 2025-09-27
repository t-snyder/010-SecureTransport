package core.utils;


import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapList;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;


public class ConfigReader
{
  private final KubernetesClient kubeClient;
  private final String           nameSpace;

  public ConfigReader()
  {
    this.kubeClient = new KubernetesClientBuilder().build();
    this.nameSpace  = kubeClient.getNamespace();
  }
  
  public ConfigReader( String nameSpace )
  {
    // Create a Kubernetes client
    this.kubeClient = new KubernetesClientBuilder().build();
    this.nameSpace  = nameSpace;
  }

  public String getConfigMapNameFromEnv( String envVar )
  {
    return System.getenv( envVar );
  }
  
  public List<String> getNamespaceConfigMaps( String nameSpace )
  {
    List<String>  configMapNames = new ArrayList<String>();
    ConfigMapList configMapList  = kubeClient.configMaps().inNamespace( nameSpace ).list();

    for( ConfigMap item : configMapList.getItems() )
    {
      configMapNames.add( item.getMetadata().getName() );
    }
    
    return configMapNames;
  }
  
  public String getConfigMapValue( String configMapName, String key )
  {
    // Get the ConfigMap from the specified namespace
    ConfigMap configMap = kubeClient.configMaps().inNamespace( nameSpace ).withName( configMapName ).get();

    if( configMap != null )
    {
      // Return the value associated with the specified key
      return configMap.getData().get( key );
    } 
    else
    {
      throw new RuntimeException( "ConfigMap not found: " + configMapName );
    }
  }
  
  public Map<String, String> getConfigProperties( String configMapName )
  {
    ConfigMap  configMap = kubeClient.configMaps().inNamespace( nameSpace ).withName( configMapName ).get();

    if( configMap != null )
    {
      return configMap.getData();
     } 
    else
    {
      throw new RuntimeException( "ConfigMap not found: " + configMapName );
    }
  }

  public KubernetesClient getKubeClient() { return kubeClient; }
  public String           getNamespace()  { return nameSpace;  }
  
  public void close()
  {
    // Close the Kubernetes client
    kubeClient.close();
  }
}
