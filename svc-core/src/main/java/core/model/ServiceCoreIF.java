package core.model;

public interface ServiceCoreIF
{
  public static final String SUCCESS = "success";
  public static final String FAILURE = "failure";

  public static final int    DilithiumLevel = 5;
  // Key Services
  public static final String MetadataSvcId = "metadata";
  public static final String WatcherSvcId  = "watcher";
  
  // Message Header attributes
  public static final String MsgHeaderSourceSvcID   = "SourceSvcID";
  public static final String MsgHeaderTargetSvcID   = "TargetSvcID";
  public static final String MsgHeaderEventType     = "EventType";
  public static final String MsgHeaderCorrelationId = "CorrelationId";
  public static final String MsgHeaderTimeStamp     = "TimeStamp";
  public static final String MsgHeaderVersion       = "Version";

  // Key Exchange
  public static final String KyberMsgKey      = "kyberExchange";      // Key exchange msg key
  public static final String KyberKeyRequest  = "KyberKeyRequest";    // Key exchange request msg event Type
  public static final String KyberKeyResponse = "KyberKeyResponse";   // Key exchange response msg event Type

  // Key Rotation
  public static final String KyberRotateKey      = "kyberRotateMsgKey";   // Key rotate request msg key
  public static final String KyberRotateRequest  = "KyberRotateRequest";  // Key rotate request event msg Type
  public static final String KyberRotateResponse = "KyberRotateResponse"; // Key rotate response event msg Type

  // Topics
  public static final String MetaDataClientRequestStream      = "metadata/client/request";      // topic for metadata service receiving a client request client data
  public static final String MetaDataClientNotificationStream = "metadata/client/notification"; // topic for metadata service sending data available to all subscribers
  public static final String MetaDataClientCaCertStream       = "metadata/client/ca-cert";                   // nats stream for sending clients updated ca-certificate bundles 

  public static final String KeyExchangeStreamBase   = "metadata/bundle-pull/svc-";      // topic for metadata service to receive a key exchange request
  public static final String BundlePushStreamBase    = "metadata/bundle-push/svc-";      // topic for metadata service to receive a key exchange request

  // Service configMap default env key
  public static final String ConfDefaultKey     = "serviceConfig";
  public static final long   KeyRotationMinutes = 10;
  
  public static final String CaRotationEvent = "CaRotationEvent";

}
