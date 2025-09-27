package utils;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.model.WatcherIF;

public class WatcherConfig
{
  private static final Logger LOGGER = LoggerFactory.getLogger( WatcherConfig.class );

  private String serviceId         = "watcher";
  private String watcherCerts      = null;
  private String proxyTLSSecret    = null;
  private String natsUseTLS        = null;
  private String natsUseAuth       = null;
  private String natsProxyURL      = null;
  private String natsAdminURL      = null;
  private String natsCertPath      = null;
  private String natsCaPath        = null;
  private String natsCaSecret      = null;

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
    if( data.get( WatcherIF.WatcherCerts        ) != null ) watcherCerts      = data.get( WatcherIF.WatcherCerts        );
    if( data.get( WatcherIF.ProxyCertSecretName ) != null ) proxyTLSSecret    = data.get( WatcherIF.ProxyCertSecretName );
    if( data.get( WatcherIF.NatsUseTLS          ) != null ) natsUseTLS        = data.get( WatcherIF.NatsUseTLS          );
    if( data.get( WatcherIF.NatsUseAuth         ) != null ) natsUseAuth       = data.get( WatcherIF.NatsUseAuth         );
    if( data.get( WatcherIF.NatsProxyURL        ) != null ) natsProxyURL      = data.get( WatcherIF.NatsProxyURL        );
    if( data.get( WatcherIF.NatsAdminURL        ) != null ) natsAdminURL      = data.get( WatcherIF.NatsAdminURL        );
    if( data.get( WatcherIF.NatsCaPath          ) != null ) natsCaPath        = data.get( WatcherIF.NatsCaPath          );
    if( data.get( WatcherIF.NatsCertPath        ) != null ) natsCertPath      = data.get( WatcherIF.NatsCertPath        );
    if( data.get( WatcherIF.NatsCaSecret        ) != null ) natsCaSecret      = data.get( WatcherIF.NatsCaSecret        );

    if( data.get( WatcherIF.VaultAgentHost      ) != null ) vaultAgentHost    = data.get( WatcherIF.VaultAgentHost      );
    if( data.get( WatcherIF.SecretIDRotationMs  ) != null ) secretIDRotationMs = data.get( WatcherIF.SecretIDRotationMs  );

    if( data.get( WatcherIF.NatsAgentAddr           ) != null ) natsAgentAddr   = data.get( WatcherIF.NatsAgentAddr     );
    if( data.get( WatcherIF.NatsAgentPort           ) != null ) natsAgentPort   = data.get( WatcherIF.NatsAgentPort     );
    if( data.get( WatcherIF.NatsAppRoleSecretName   ) != null ) natsAppRoleSecretName  = data.get( WatcherIF.NatsAppRoleSecretName   );
    if( data.get( WatcherIF.NatsAppRoleName         ) != null ) natsAppRoleName  = data.get( WatcherIF.NatsAppRoleName  );
    if( data.get( WatcherIF.NatsAgentTokenPath      ) != null ) natsAgentTokenPath  = data.get( WatcherIF.NatsAgentTokenPath   );

    if( data.get( WatcherIF.WatcherAgentAddr         ) != null ) watcherAgentAddr  = data.get( WatcherIF.WatcherAgentAddr    );
    if( data.get( WatcherIF.WatchergentPort          ) != null ) watcherAgentPort  = data.get( WatcherIF.WatchergentPort     );
    if( data.get( WatcherIF.WatcherAppRoleSecretName ) != null ) watcherAppRoleSecretName = data.get( WatcherIF.WatcherAppRoleSecretName );
    if( data.get( WatcherIF.WatcherAppRoleName       ) != null ) watcherAppRoleName  = data.get( WatcherIF.WatcherAppRoleName   );
    if( data.get( WatcherIF.WatcherAgentTokenPath    ) != null ) watcherAgentTokenPath  = data.get( WatcherIF.WatcherAgentTokenPath     );

    LOGGER.info( "***************** NATS Watcher Config is set for ******************" );
    LOGGER.info( WatcherIF.WatcherCerts + "        = " + watcherCerts      );
    LOGGER.info( WatcherIF.ProxyCertSecretName + " = " + proxyTLSSecret    );
    LOGGER.info( WatcherIF.NatsUseTLS + "          = " + natsUseTLS        );
    LOGGER.info( WatcherIF.NatsUseAuth + "         = " + natsUseAuth       );
    LOGGER.info( WatcherIF.NatsProxyURL + "        = " + natsProxyURL      );
    LOGGER.info( WatcherIF.NatsAdminURL + "        = " + natsAdminURL      );
    LOGGER.info( WatcherIF.NatsCertPath + "        = " + natsCertPath      );
    LOGGER.info( WatcherIF.NatsCaPath + "          = " + natsCaPath        );
    LOGGER.info( "***************** End of NATS Watcher Config ******************" );
  }

  public String getServiceId()      { return serviceId;      }
  public String getWatcherCerts()   { return watcherCerts;   }
  public String getProxyTLSSecret() { return proxyTLSSecret; }
  public String getNatsUseTLS()     { return natsUseTLS;     }
  public String getNatsUseAuth()    { return natsUseAuth;    }
  public String getNatsURL()        { return natsProxyURL;   }
  public String getNatsCertPath()   { return natsCertPath;   }
  public String getNatsCaPath()     { return natsCaPath;     }
  public String getNatsCaSecret()   { return natsCaSecret;   }
  public String getNatsAdminURL()   { return natsAdminURL;   }

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