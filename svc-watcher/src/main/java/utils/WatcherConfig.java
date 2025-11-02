package utils;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.model.WatcherIF;

public class WatcherConfig
{
  private static final Logger LOGGER = LoggerFactory.getLogger( WatcherConfig.class );

  private String serviceId   = "watcher";
  private String environment = null;

  private String natsUseTLS     = null;
  private String natsURL        = null;
  private String tlsSecret      = null;
  private String caCertFilePath = null;
  private String clientCertPath = null;

  private String vaultAgentHost           = null;
  private String secretIDRotationMs       = null;

  private String natsAgentAddr            = null;
  private String natsAgentPort            = null;
  private String natsAppRoleSecretName    = null;
  private String natsAppRoleName          = null;
  private String natsAgentTokenPath       = null;

  private String watcherAgentAddr         = null;
  private String watcherAgentPort         = null;
  private String watcherAppRoleSecretName = null;
  private String watcherAppRoleName       = null;
  private String watcherAgentTokenPath    = null;

  public WatcherConfig( Map<String, String> data )
  {
    if( data.get( WatcherIF.ServiceId      ) != null ) serviceId      = data.get( WatcherIF.ServiceId      );
    if( data.get( WatcherIF.Environment    ) != null ) environment    = data.get( WatcherIF.Environment );
    if( data.get( WatcherIF.NatsUseTLS     ) != null ) natsUseTLS     = data.get( WatcherIF.NatsUseTLS          );
    if( data.get( WatcherIF.NatsURL        ) != null ) natsURL        = data.get( WatcherIF.NatsURL        );
    if( data.get( WatcherIF.TlsSecret      ) != null ) tlsSecret      = data.get( WatcherIF.TlsSecret        );
    if( data.get( WatcherIF.CaCertFilePath ) != null ) caCertFilePath = data.get( WatcherIF.CaCertFilePath          );
    if( data.get( WatcherIF.ClientCertPath ) != null ) clientCertPath = data.get( WatcherIF.ClientCertPath        );

    if( data.get( WatcherIF.VaultAgentHost     ) != null ) vaultAgentHost     = data.get( WatcherIF.VaultAgentHost      );
    if( data.get( WatcherIF.SecretIDRotationMs ) != null ) secretIDRotationMs = data.get( WatcherIF.SecretIDRotationMs  );

    if( data.get( WatcherIF.NatsAgentAddr         ) != null ) natsAgentAddr         = data.get( WatcherIF.NatsAgentAddr     );
    if( data.get( WatcherIF.NatsAgentPort         ) != null ) natsAgentPort         = data.get( WatcherIF.NatsAgentPort     );
    if( data.get( WatcherIF.NatsAppRoleSecretName ) != null ) natsAppRoleSecretName = data.get( WatcherIF.NatsAppRoleSecretName   );
    if( data.get( WatcherIF.NatsAppRoleName       ) != null ) natsAppRoleName       = data.get( WatcherIF.NatsAppRoleName  );
    if( data.get( WatcherIF.NatsAgentTokenPath    ) != null ) natsAgentTokenPath    = data.get( WatcherIF.NatsAgentTokenPath   );

    if( data.get( WatcherIF.WatcherAgentAddr         ) != null ) watcherAgentAddr  = data.get( WatcherIF.WatcherAgentAddr    );
    if( data.get( WatcherIF.WatchergentPort          ) != null ) watcherAgentPort  = data.get( WatcherIF.WatchergentPort     );
    if( data.get( WatcherIF.WatcherAppRoleSecretName ) != null ) watcherAppRoleSecretName = data.get( WatcherIF.WatcherAppRoleSecretName );
    if( data.get( WatcherIF.WatcherAppRoleName       ) != null ) watcherAppRoleName  = data.get( WatcherIF.WatcherAppRoleName   );
    if( data.get( WatcherIF.WatcherAgentTokenPath    ) != null ) watcherAgentTokenPath  = data.get( WatcherIF.WatcherAgentTokenPath     );
   
    LOGGER.info( "***************** NATS Watcher Config is set for ******************" );
    LOGGER.info( WatcherIF.ServiceId + "      = " + serviceId      );
    LOGGER.info( WatcherIF.Environment + "    = " + environment    );
    LOGGER.info( WatcherIF.NatsUseTLS + "     = " + natsUseTLS     );
    LOGGER.info( WatcherIF.NatsURL + "        = " + natsURL        );
    LOGGER.info( WatcherIF.TlsSecret + "      = " + tlsSecret      );
    LOGGER.info( WatcherIF.CaCertFilePath + " = " + caCertFilePath );
    LOGGER.info( WatcherIF.ClientCertPath + " = " + clientCertPath );
    LOGGER.info( WatcherIF.VaultAgentHost + " = " + vaultAgentHost );
    LOGGER.info( "***************** End of NATS Watcher Config ******************" );
  }

  public String getServiceId()      { return serviceId;      }
  public String getEnvironment()    { return environment;    }
  public String getNatsUseTLS()     { return natsUseTLS;     }
  public String getNatsURL()        { return natsURL;        }
  public String getTLSSecret()      { return tlsSecret;      }
  public String getCaCertFilePath() { return caCertFilePath; }
  public String getClientCertPath() { return clientCertPath; }

  public String getVaultAgentHost()     { return vaultAgentHost;     }
  public String getSecretIDRotationMs() { return secretIDRotationMs; }

  public String getNatsAgentAddr()          { return natsAgentAddr;          }
  public String getNatsAgentPort()          { return natsAgentPort;          }
  public String getNatsAppRoleSecretName()  { return natsAppRoleSecretName;  }
  public String getNatsAppRoleName()        { return natsAppRoleName;        }
  public String getNatsAgentTokenPath()     { return natsAgentTokenPath;     }

  public String getWatcherAgentAddr()         { return watcherAgentAddr;         }
  public String getWatcherAgentPort()         { return watcherAgentPort;         }
  public String getWatcherAppRoleSecretName() { return watcherAppRoleSecretName; }
  public String getWatcherAppRoleName()       { return watcherAppRoleName;       }
  public String getWatcherAgentTokenPath()    { return watcherAgentTokenPath;    }

}