package core.model;


public interface WatcherIF
{
  // Kube Watcher Conf Keys
  public static final String KubeClusterName     = "KUBE_CLUSTER_NAME";
  public static final String WatcherNameSpace    = "WATCHER_NAMESPACE";
  public static final String WatcherCerts        = "watcherCerts";
  public static final String WatcherLogLevel     = "WATCHER_LOG_LEVEL";

  // Pulsar Watcher Secret conf Keys
  public static final String CaCertSecretName    = "ca-cert";
  public static final String ProxyCertSecretName = "tls-cert";
  public static final String NatsUseTLS        = "natsUseTLS";
  public static final String NatsUseAuth       = "natsUseAuth";
  public static final String NatsProxyURL      = "natsUrl";
  public static final String NatsAdminURL      = "natsAdminUrl";
  public static final String NatsCaPath        = "natsCaPath";  
  public static final String NatsCertPath      = "natsCertPath";  
  public static final String NatsCaSecret      = "natsCaSecret";  

  public static final String VaultAgentHost      = "vaultAgentHost";
  public static final String SecretIDRotationMs  = "secretIDRotationMs";
  
  public static final String NatsAgentAddr         = "natsAgentAddr";
  public static final String NatsAgentPort         = "natsAgentPort";
  public static final String NatsAppRoleSecretName = "natsAppRoleSecretName";
  public static final String NatsAppRoleName       = "natsAppRoleName";
  public static final String NatsAgentTokenPath    = "natsAgentTokenPath";
  
  public static final String WatcherAgentAddr         = "watcherAgentAddr";
  public static final String WatchergentPort          = "watcherAgentPort";
  public static final String WatcherAppRoleSecretName = "watcherAppRoleSecretName";
  public static final String WatcherAppRoleName       = "watcherAppRoleName";
  public static final String WatcherAgentTokenPath    = "watcherAgentTokenPath";
  
  // Certificate path
  public static final String CertPath            = "CertPath";

  // Watcher certificate message - event types and msg keys
  public static final String CertInitial  = "CertInitial";
  public static final String CertAdded    = "CertAdded";
  public static final String CertModified = "CertModified";
  public static final String CertDeleted  = "CertDeleted";

}
