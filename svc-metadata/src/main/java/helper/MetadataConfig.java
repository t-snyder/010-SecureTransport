package helper;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class MetadataConfig
{
  private String kubeClusterName;
  private String serviceId;
  private String environment;
  
  private NatsConfig            nats;
  private VaultConfig           vault;
  private KeyExchangeConfig     keyExchange;
  private ServicesACLConfig     servicesACL;

  // New fields from the revised JSON
  private List<Map<String, List<String>>> transportKeys;

  // Getters
  public String            getKubeClusterName() { return kubeClusterName; }
  public String            getServiceId()       { return serviceId;       }
  public String            getEnvironment()     { return environment;     }
  public NatsConfig        getNats()            { return nats;            }
  public VaultConfig       getVault()           { return vault;           }
  public KeyExchangeConfig getKeyExchange()     { return keyExchange;     }
  public ServicesACLConfig getServicesACL()     { return servicesACL;     }
  
  public List<Map<String, List<String>>> getTransportKeys() { return transportKeys; }

  
  // Static method to load config from JSON file
  public static MetadataConfig fromFile( String path ) throws IOException
  {
    ObjectMapper mapper = new ObjectMapper();
    return mapper.readValue( new File( path ), MetadataConfig.class );
  }

  // Nested Classes
  public static class NatsConfig
  {
    @JsonProperty( "natsServers"           ) private String natsServers;
    @JsonProperty( "natsUseTLS"            ) private String natsUseTLS;
    @JsonProperty( "natsCredentialsFile"   ) private String natsCredentialsFile;
    @JsonProperty( "natsJwtFile"           ) private String natsJwtFile;
    @JsonProperty( "natsNkeyFile"          ) private String natsNkeyFile;
    @JsonProperty( "natsCaCertFile"        ) private String natsCaCertFile;
    @JsonProperty( "natsClientCertFile"    ) private String natsClientCertFile;
    @JsonProperty( "natsClientKeyFile"     ) private String natsClientKeyFile;
    @JsonProperty( "natsConnectionName"    ) private String natsConnectionName;
    @JsonProperty( "jetstreamDomain"       ) private String jetstreamDomain;
    @JsonProperty( "maxReconnectAttempts"  ) private String maxReconnectAttempts;
    @JsonProperty( "reconnectWaitMs"       ) private String reconnectWaitMs;
    @JsonProperty( "connectionTimeoutMs"   ) private String connectionTimeoutMs;

    public String getNatsServers()          { return natsServers;          }
    public String getNatsUseTLS()           { return natsUseTLS;           }
    public String getNatsCredentialsFile()  { return natsCredentialsFile;  }
    public String getNatsJwtFile()          { return natsJwtFile;          }
    public String getNatsNkeyFile()         { return natsNkeyFile;         }
    public String getNatsCaCertFile()       { return natsCaCertFile;       }
    public String getNatsClientCertFile()   { return natsClientCertFile;   }
    public String getNatsClientKeyFile()    { return natsClientKeyFile;    }
    public String getNatsConnectionName()   { return natsConnectionName;   }
    public String getJetstreamDomain()      { return jetstreamDomain;      }
    public String getMaxReconnectAttempts() { return maxReconnectAttempts; }
    public String getReconnectWaitMs()      { return reconnectWaitMs;      }
    public String getConnectionTimeoutMs()  { return connectionTimeoutMs;  }
  }

  public static class VaultConfig
  {
    @JsonProperty( "vaultagentAddr"     ) private String vaultAgentAddr;
    @JsonProperty( "vaultAgentHost"     ) private String vaultAgentHost;
    @JsonProperty( "vaultAgentPort"     ) private String vaultAgentPort;
    @JsonProperty( "appRoleSecretName"  ) private String appRoleSecretName;
    @JsonProperty( "appRoleName"        ) private String appRoleName;
    @JsonProperty( "appRoleTokenPath"   ) private String appRoleTokenPath;
    @JsonProperty( "secretIDRotationMs" ) private String secretIDRotationMs;

    public String getVaultAgentAddr()     { return vaultAgentAddr;     }
    public String getVaultAgentHost()     { return vaultAgentHost;     }
    public String getVaultAgentPort()     { return vaultAgentPort;     }
    public String getAppRoleSecretName()  { return appRoleSecretName;  }
    public String getAppRoleName()        { return appRoleName;        }
    public String getAppRoleTokenPath()   { return appRoleTokenPath;   }
    public String getSecretIDRotationMs() { return secretIDRotationMs; }
  }

  public static class KeyExchangeConfig
  {
    @JsonProperty( "keyRotationMinutes"  ) private String keyRotationMinutes;
    @JsonProperty( "svcKeyExchStreamBase") private String svcKeyExchStreamBase;
    @JsonProperty( "expiryMinutes"       ) private String expiryMinutes;
    @JsonProperty( "consumerStreamSvcId" ) private String consumerStreamSvcId;
    @JsonProperty( "producerStreamSvcIds") private List<String> producerStreamSvcIds;

    public String       getKeyRotationMinutes()   { return keyRotationMinutes;   }
    public String       getSvcKeyExchStreamBase() { return svcKeyExchStreamBase; }
    public String       getExpiryMinutes()        { return expiryMinutes;        }
    public String       getConsumerStreamSvcId()  { return consumerStreamSvcId;  }
    public List<String> getProducerStreamSvcIds() { return producerStreamSvcIds; }
  }
  
  public static class ServicesACLConfig
  {
    @JsonProperty( "aclConfigMapName" ) private String aclConfigMapName;
    @JsonProperty( "aclNamespace"     ) private String aclNamespace;
    @JsonProperty( "encKeyExpiry"     ) private String encKeyExpiry;
    @JsonProperty( "rotatePriorHours" ) private String rotatePriorHours;
   
    public String getAclConfigMapName() { return aclConfigMapName; }
    public String getAclNamespace()     { return aclNamespace;     }
    public String getEncKeyExpiry()     { return encKeyExpiry;     }
    public String getRotatePriorHours() { return rotatePriorHours; }
  }
}