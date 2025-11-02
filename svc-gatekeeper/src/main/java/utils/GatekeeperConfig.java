package utils;


import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * GatekeeperConfig serviceId natsURL tlsSecret caCertPath clientCertPath
 *
 * gatekeeperRequestTopic (optional – only if you keep an intake subject)
 * gatekeeperResponseTopic (REQUIRED – where Gatekeeper listens for auth
 * responses) authControllerRequestTopic (REQUIRED – where Gatekeeper publishes
 * auth requests)
 *
 * vaultAgentHost gatewayAgentAddr gatewayAgentPort gatewayAgentTokenPath
 *
 * gatewayAppRoleName gatewayAppRoleSecretName secretIDRotationMs
 *
 * producerBatchSize consumerBatchSize maxConcurrentRequests requestTimeoutMs
 * keyRotationIntervalMs
 *
 * ratePerSecond userCount
 */
public class GatekeeperConfig
{
  private static final Logger LOGGER = LoggerFactory.getLogger( GatekeeperConfig.class );

  // Service Identity
  private final String serviceId;

  // NATS Configuration
  private final String natsURL;
  private final String tlsSecret;
  private final String caCertPath;
  private final String clientCertPath;

  // Messaging Subjects
  private final String gatekeeperRequestTopic; // optional (can be unused)
  private final String gatekeeperResponseTopic; // responses from AuthController
  private final String authControllerRequestTopic; // outbound auth requests

  // Bao / Agent Configuration
  private final String baoAgentHost;
  private final String gatewayAgentAddr;
  private final String gatewayAgentPort;
  private final String gatewayAgentTokenPath;

  // AppRole Configuration
  private final String gatewayAppRoleName;
  private final String gatewayAppRoleSecretName;
  private final String secretIDRotationMs;

  // Performance / Rotation
  private final String producerBatchSize;
  private final String consumerBatchSize;
  private final String maxConcurrentRequests;
  private final String requestTimeoutMs;
  private final String keyRotationIntervalMs;

  // Load Generator
  private final int ratePerSecond;
  private final int userCount;

  public GatekeeperConfig( Map<String, String> configData )
  {
    if( configData == null || configData.isEmpty() )
    {
      throw new IllegalArgumentException( "Configuration data cannot be null or empty" );
    }

    try
    {
      // Service Identity
      this.serviceId = getRequired( configData, "serviceId", "gatekeeper" );

      // NATS
      this.natsURL = getRequired( configData, "natsURL" );
      this.tlsSecret = getRequired( configData, "tlsSecret" );
      this.caCertPath = getRequired( configData, "caCertPath", "/app/certs/nats-ca-certs/ca.crt" );
      this.clientCertPath = getRequired( configData, "clientCertPath", "/app/certs/nats-client-certs/" );

      // Subjects
      this.gatekeeperRequestTopic = getRequired( configData, "gatekeeperRequestTopic", "gatekeeper.requests" );
      this.gatekeeperResponseTopic = getRequired( configData, "gatekeeperResponseTopic", "gatekeeper.responder" );
      this.authControllerRequestTopic = getRequired( configData, "authControllerRequestTopic", "auth.auth-request" );

      // Vault / Agent
      this.baoAgentHost = getRequired( configData,          "baoAgentHost" );
      this.gatewayAgentAddr = getRequired( configData,      "gatewayAgentAddr" );
      this.gatewayAgentPort = getRequired( configData,      "gatewayAgentPort", "8200" );
      this.gatewayAgentTokenPath = getRequired( configData, "gatewayAgentTokenPath", "/home/vault/gatekeeper" );

      // AppRole
      this.gatewayAppRoleName = getRequired( configData, "gatewayAppRoleName", "gatekeeper" );
      this.gatewayAppRoleSecretName = getRequired( configData, "gatewayAppRoleSecretName", "gatekeeper-vault-approle" );
      this.secretIDRotationMs = getRequired( configData, "secretIDRotationMs", "3600000" ); // 1
                                                                                            // hour

      // Performance
      this.producerBatchSize = getRequired( configData, "producerBatchSize", "1000" );
      this.consumerBatchSize = getRequired( configData, "consumerBatchSize", "1000" );
      this.maxConcurrentRequests = getRequired( configData, "maxConcurrentRequests", "10000" );
      this.requestTimeoutMs = getRequired( configData, "requestTimeoutMs", "30000" );
      this.keyRotationIntervalMs = getRequired( configData, "keyRotationIntervalMs", "10800000" ); // 3
                                                                                                   // hours

      // Load Generator
      this.ratePerSecond = Integer.parseInt( getRequired( configData, "ratePerSecond", "10" ) );
      this.userCount = Integer.parseInt( getRequired( configData, "userCount", "5" ) );

      logConfig();
    }
    catch( Exception e )
    {
      LOGGER.error( "Error initializing GatekeeperConfig: {}", e.getMessage(), e );
      throw new RuntimeException( "Failed to initialize Gatekeeper configuration", e );
    }
  }

  // ---------- Helpers ----------
  private String getRequired( Map<String, String> data, String key )
  {
    return getRequired( data, key, null );
  }

  private String getRequired( Map<String, String> data, String key, String def )
  {
    String v = data.get( key );
    if( v == null || v.trim().isEmpty() )
    {
      if( def != null )
      {
        LOGGER.debug( "Using default for {}: {}", key, def );
        return def;
      }
      throw new IllegalArgumentException( "Missing required config key: " + key );
    }
    return v.trim();
  }

  private void logConfig()
  {
    LOGGER.info( "Gatekeeper Configuration:" );
    LOGGER.info( "  Service ID: {}", serviceId );
    LOGGER.info( "  NATS URL: {}", natsURL );
    LOGGER.info( "  Gatekeeper Response Subject: {}", gatekeeperResponseTopic );
    LOGGER.info( "  AuthController Request Subject: {}", authControllerRequestTopic );
    LOGGER.info( "  Producer Batch Size: {}", producerBatchSize );
    LOGGER.info( "  Consumer Batch Size: {}", consumerBatchSize );
    LOGGER.info( "  Max Concurrent Requests: {}", maxConcurrentRequests );
    LOGGER.info( "  Request Timeout: {} ms", requestTimeoutMs );
    LOGGER.info( "  Key Rotation Interval: {} ms", keyRotationIntervalMs );
    LOGGER.info( "  Secret ID Rotation: {} ms", secretIDRotationMs );
    LOGGER.info( "  Load Rate (msg/sec): {}", ratePerSecond );
    LOGGER.info( "  User Count: {}", userCount );
  }

  // ---------- Getters ----------
  public String getServiceId()
  {
    return serviceId;
  }

  public String getNatsURL()
  {
    return natsURL;
  }

  public String getTlsSecret()
  {
    return tlsSecret;
  }

  public String getCaCertPath()
  {
    return caCertPath;
  }

  public String getClientCertPath()
  {
    return clientCertPath;
  }

  public String getGatekeeperRequestTopic()
  {
    return gatekeeperRequestTopic;
  }

  public String getGatekeeperResponseTopic()
  {
    return gatekeeperResponseTopic;
  }

  public String getAuthControllerRequestTopic()
  {
    return authControllerRequestTopic;
  }

  public String getBaoAgentHost()
  {
    return baoAgentHost;
  }

  public String getGatewayAgentAddr()
  {
    return gatewayAgentAddr;
  }

  public String getGatewayAgentPort()
  {
    return gatewayAgentPort;
  }

  public String getGatewayAgentTokenPath()
  {
    return gatewayAgentTokenPath;
  }

  public String getGatewayAppRoleName()
  {
    return gatewayAppRoleName;
  }

  public String getGatewayAppRoleSecretName()
  {
    return gatewayAppRoleSecretName;
  }

  public String getSecretIDRotationMs()
  {
    return secretIDRotationMs;
  }

  public String getProducerBatchSize()
  {
    return producerBatchSize;
  }

  public String getConsumerBatchSize()
  {
    return consumerBatchSize;
  }

  public String getMaxConcurrentRequests()
  {
    return maxConcurrentRequests;
  }

  public String getRequestTimeoutMs()
  {
    return requestTimeoutMs;
  }

  public String getKeyRotationIntervalMs()
  {
    return keyRotationIntervalMs;
  }

  public int getRatePerSecond()
  {
    return ratePerSecond;
  }

  public int getUserCount()
  {
    return userCount;
  }

  // ---------- Numeric Conversions ----------
  public int getProducerBatchSizeInt()
  {
    return Integer.parseInt( producerBatchSize );
  }

  public int getConsumerBatchSizeInt()
  {
    return Integer.parseInt( consumerBatchSize );
  }

  public int getMaxConcurrentRequestsInt()
  {
    return Integer.parseInt( maxConcurrentRequests );
  }

  public long getRequestTimeoutMsLong()
  {
    return Long.parseLong( requestTimeoutMs );
  }

  public long getKeyRotationIntervalMsLong()
  {
    return Long.parseLong( keyRotationIntervalMs );
  }

  public long getSecretIDRotationMsLong()
  {
    return Long.parseLong( secretIDRotationMs );
  }
}