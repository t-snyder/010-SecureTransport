package model;

public interface MetadataSvcIF
{
  // Event Bus
  public static final String EventBusKyberResponse = "kyber.keyResponse";

  // MetadataService Config keys
  public static final String NatsUseTLS           = "natsUseTLS";
  public static final String NatsServers          = "natsServers";
  public static final String NatsCredentialsFile  = "natsCredentialsFile";
  public static final String NatsCACertPath       = "natsCaCertFile";
  public static final String NatsClientCertPath   = "natsClientCertFile";
  public static final String NatsClientKeyPath    = "natsClientKeyFile";
  public static final String VaultAgentUrl        = "agentAddr";
  public static final String DeploymentNamespace  = "namespace";
  public static final String VaultAppRoleSecret   = "vaultAppRoleSecret";
  public static final String VaultAppRoleRoleName = "vaultRoleName";
  public static final String DeploymentName       = "appDeploymentName";
}