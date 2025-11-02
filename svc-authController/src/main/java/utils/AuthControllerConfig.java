package utils;


import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configuration class for AuthController Service Reads configuration from
 * Kubernetes ConfigMap data
 */
public class AuthControllerConfig
{
  private static final Logger LOGGER = LoggerFactory.getLogger( AuthControllerConfig.class );

  // Service Identity
  private String serviceId;

  // Nats Configuration
  private String natsURL;
  private String tlsSecret;
  private String caCertPath;
  private String clientCertPath;

  // Gateway Topics (AuthController consumes from Gatekeeper's request topic and
  // sends to response topic)
  private String gatekeeperRequestTopic;
  private String gatekeeperResponseTopic;

  // OpenBao Configuration
  private String baoAgentHost;
  private String authControllerAgentAddr;
  private String authControllerAgentPort;
  private String authControllerAgentTokenPath;

  // AppRole Configuration
  private String authControllerAppRoleName;
  private String authControllerAppRoleSecretName;
  private String secretIDRotationMs;

  // Performance Configuration
  private String producerBatchSize;
  private String consumerBatchSize;
  private String maxConcurrentRequests;
  private String requestTimeoutMs;
  private String keyRotationIntervalMs;

  // AuthController specific configuration
  private String authTokenValidityMs;
  private String maxAuthAttempts;
  private String authCacheSize;
  private String downtimeTrackingEnabled;

  public AuthControllerConfig( Map<String, String> configData )
  {
    if( configData == null || configData.isEmpty() )
    {
      throw new IllegalArgumentException( "Configuration data cannot be null or empty" );
    }

    try
    {
      // Service Identity
      this.serviceId = getRequiredConfig( configData, "serviceId", "authcontroller" );

      // Nats Configuration
      this.natsURL        = getRequiredConfig( configData, "natsURL" );
      this.tlsSecret      = getRequiredConfig( configData, "tlsSecret" );
      this.caCertPath     = getRequiredConfig( configData, "caCertPath",     "/app/certs//nats-ca-certs/ca.crt" );
      this.clientCertPath = getRequiredConfig( configData, "clientCertPath", "/app/certs/nats-client-certs/" );

      // Gateway Topics (consume from gatekeeper requests, send to gatekeeper responses)
      this.gatekeeperRequestTopic  = getRequiredConfig( configData, "gatewayRequestTopic",  "auth.auth-request" );
      this.gatekeeperResponseTopic = getRequiredConfig( configData, "gatewayResponseTopic", "gatekeeper.responder" );

      // Vault Configuration
      this.baoAgentHost                 = getRequiredConfig( configData, "baoAgentHost" );
      this.authControllerAgentAddr      = getRequiredConfig( configData, "authControllerAgentAddr" );
      this.authControllerAgentPort      = getRequiredConfig( configData, "authControllerAgentPort", "8200" );
      this.authControllerAgentTokenPath = getRequiredConfig( configData, "authControllerAgentTokenPath", "/home/bao/authcontroller" );

      // AppRole Configuration
      this.authControllerAppRoleName       = getRequiredConfig( configData, "authControllerAppRoleName", "authcontroller-approle" );
      this.authControllerAppRoleSecretName = getRequiredConfig( configData, "authControllerAppRoleSecretName", "authcontroller-bao-approle" );
      this.secretIDRotationMs              = getRequiredConfig( configData, "secretIDRotationMs", "3600000" ); // 1
                                                                                                  // hour

      // Performance Configuration
      this.producerBatchSize     = getRequiredConfig( configData, "producerBatchSize", "1000" );
      this.consumerBatchSize     = getRequiredConfig( configData, "consumerBatchSize", "1000" );
      this.maxConcurrentRequests = getRequiredConfig( configData, "maxConcurrentRequests", "10000" );
      this.requestTimeoutMs      = getRequiredConfig( configData, "requestTimeoutMs", "30000" );
      this.keyRotationIntervalMs = getRequiredConfig( configData, "keyRotationIntervalMs", "10800000" ); // 3
                                                                                                         // hours

      // AuthController specific configuration
      this.authTokenValidityMs = getRequiredConfig( configData, "authTokenValidityMs", "3600000" ); // 1
                                                                                                    // hour
      this.maxAuthAttempts         = getRequiredConfig( configData, "maxAuthAttempts", "5" );
      this.authCacheSize           = getRequiredConfig( configData, "authCacheSize", "10000" );
      this.downtimeTrackingEnabled = getRequiredConfig( configData, "downtimeTrackingEnabled", "true" );

      LOGGER.info( "AuthControllerConfig initialized successfully for service: {}", this.serviceId );
      logConfiguration();

    } 
    catch( Exception e )
    {
      LOGGER.error( "Error initializing AuthControllerConfig: {}", e.getMessage(), e );
      throw new RuntimeException( "Failed to initialize authcontroller configuration", e );
    }
  }

  /**
   * Get required configuration value with optional default
   */
  private String getRequiredConfig( Map<String, String> configData, String key, String defaultValue )
  {
    String value = configData.get( key );
    if( value == null || value.trim().isEmpty() )
    {
      if( defaultValue != null )
      {
        LOGGER.debug( "Using default value for {}: {}", key, defaultValue );
        return defaultValue;
      } 
      else
      {
        throw new IllegalArgumentException( "Required configuration missing: " + key );
      }
    }
    return value.trim();
  }

  /**
   * Get required configuration value without default
   */
  private String getRequiredConfig( Map<String, String> configData, String key )
  {
    return getRequiredConfig( configData, key, null );
  }

  /**
   * Log the configuration (excluding sensitive data)
   */
  private void logConfiguration()
  {
    LOGGER.info( "AuthController Configuration:" );
    LOGGER.info( "  Service ID: {}", serviceId );
    LOGGER.info( "  Nats URL: {}", natsURL );
    LOGGER.info( "  Gateway Request Topic: {}", gatekeeperRequestTopic );
    LOGGER.info( "  Gateway Response Topic: {}", gatekeeperResponseTopic );
    LOGGER.info( "  Producer Batch Size: {}", producerBatchSize );
    LOGGER.info( "  Consumer Batch Size: {}", consumerBatchSize );
    LOGGER.info( "  Max Concurrent Requests: {}", maxConcurrentRequests );
    LOGGER.info( "  Request Timeout: {} ms", requestTimeoutMs );
    LOGGER.info( "  Key Rotation Interval: {} ms", keyRotationIntervalMs );
    LOGGER.info( "  Secret ID Rotation: {} ms", secretIDRotationMs );
    LOGGER.info( "  Auth Token Validity: {} ms", authTokenValidityMs );
    LOGGER.info( "  Max Auth Attempts: {}", maxAuthAttempts );
    LOGGER.info( "  Auth Cache Size: {}", authCacheSize );
    LOGGER.info( "  Downtime Tracking Enabled: {}", downtimeTrackingEnabled );
  }

  // Getters
  public String getServiceId()                       { return serviceId; }
  public String getNatsURL()                         { return natsURL; }
  public String getTlsSecret()                       { return tlsSecret; }
  public String getCaCertPath()                      { return caCertPath; }
  public String getClientCertPath()                  { return clientCertPath; }
  public String getGatekeeperRequestTopic()          { return gatekeeperRequestTopic; }
  public String getGatekeeperResponseTopic()         { return gatekeeperResponseTopic; }
  public String getBaoAgentHost()                    { return baoAgentHost; }
  public String getAuthControllerAgentAddr()         { return authControllerAgentAddr; }
  public String getAuthControllerAgentPort()         { return authControllerAgentPort; }
  public String getAuthControllerAgentTokenPath()    { return authControllerAgentTokenPath; }
  public String getAuthControllerAppRoleName()       { return authControllerAppRoleName; }
  public String getAuthControllerAppRoleSecretName() { return authControllerAppRoleSecretName; }
  public String getSecretIDRotationMs()              { return secretIDRotationMs; }
  public String getProducerBatchSize()               { return producerBatchSize; }
  public String getConsumerBatchSize()               { return consumerBatchSize; }
  public String getMaxConcurrentRequests()           { return maxConcurrentRequests; }
  public String getRequestTimeoutMs()                { return requestTimeoutMs; }
  public String getKeyRotationIntervalMs()           { return keyRotationIntervalMs; }
  public String getAuthTokenValidityMs()             { return authTokenValidityMs; }
  public String getMaxAuthAttempts()                 { return maxAuthAttempts; }
  public String getAuthCacheSize()                   { return authCacheSize; }
  public String getDowntimeTrackingEnabled()         { return downtimeTrackingEnabled; }
 
  // Utility methods for numeric conversions
  public int     getProducerBatchSizeInt()      { return Integer.parseInt(     producerBatchSize       ); }
  public int     getConsumerBatchSizeInt()      { return Integer.parseInt(     consumerBatchSize       ); }
  public int     getMaxConcurrentRequestsInt()  { return Integer.parseInt(     maxConcurrentRequests   ); }
  public long    getRequestTimeoutMsLong()      { return Long.parseLong(       requestTimeoutMs        ); }
  public long    getKeyRotationIntervalMsLong() { return Long.parseLong(       keyRotationIntervalMs   ); }
  public long    getSecretIDRotationMsLong()    { return Long.parseLong(       secretIDRotationMs      ); }
  public long    getAuthTokenValidityMsLong()   { return Long.parseLong(       authTokenValidityMs     ); }
  public int     getMaxAuthAttemptsInt()        { return Integer.parseInt(     maxAuthAttempts         ); }
  public int     getAuthCacheSizeInt()          { return Integer.parseInt(     authCacheSize           ); }
  public boolean isDowntimeTrackingEnabled()    { return Boolean.parseBoolean( downtimeTrackingEnabled ); }
}