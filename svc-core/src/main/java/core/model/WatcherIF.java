package core.model;


public interface WatcherIF
{
  // Kube Watcher Conf Keys
  public static final String ServiceId      = "serviceId";
  public static final String Environment    = "environment";

  // Pulsar Watcher Secret conf Keys
  public static final String NatsUseTLS     = "natsUseTLS";
  public static final String NatsURL        = "natsUrl";
  public static final String TlsSecret      = "tlsSecret";  
  public static final String CaCertFilePath = "caCertFilePath";  
  public static final String ClientCertPath = "clientCertPath";  

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

}
