package core.model;

import java.util.HashMap;
import java.util.Map;

import io.vertx.core.json.JsonObject;


public record PulsarMsgHeader( String sourceSvcId, String targetSvcId, String eventType, String correlationId, String timeStamp, String version )
{

  public Map<String, String> toMap()
  {
    Map<String, String> props = new HashMap<String, String>();
    
    if( !sourceSvcId.isBlank()   ) props.put( ServiceCoreIF.MsgHeaderSourceSvcID,   sourceSvcId   );
    if( !targetSvcId.isBlank()   ) props.put( ServiceCoreIF.MsgHeaderTargetSvcID,   targetSvcId   );
    if( !eventType.isBlank()     ) props.put( ServiceCoreIF.MsgHeaderEventType,     eventType     );
    if( !correlationId.isBlank() ) props.put( ServiceCoreIF.MsgHeaderCorrelationId, correlationId );
    if( !timeStamp.isBlank()     ) props.put( ServiceCoreIF.MsgHeaderTimeStamp,     timeStamp     );
    if( !version.isBlank()       ) props.put( ServiceCoreIF.MsgHeaderVersion,       version       );

    return props;
  }
  
  public JsonObject toJson()
  {
    JsonObject props = new JsonObject();

    if( sourceSvcId   != null && !sourceSvcId.isBlank()   ) props.put( ServiceCoreIF.MsgHeaderSourceSvcID,   sourceSvcId   );
    if( targetSvcId   != null && !targetSvcId.isBlank()   ) props.put( ServiceCoreIF.MsgHeaderTargetSvcID,   targetSvcId   );
    if( eventType     != null && !eventType.isBlank()     ) props.put( ServiceCoreIF.MsgHeaderEventType,     eventType     );
    if( correlationId != null && !correlationId.isBlank() ) props.put( ServiceCoreIF.MsgHeaderCorrelationId, correlationId );
    if( timeStamp     != null && !timeStamp.isBlank()     ) props.put( ServiceCoreIF.MsgHeaderTimeStamp,     timeStamp     );
    if( version       != null && !version.isBlank()       ) props.put( ServiceCoreIF.MsgHeaderVersion,       version       );

    return props;
  }
  
  public static Map<String, String> fromJson( JsonObject json )
  {
    Map<String, String> props = new HashMap<String, String>();

    if( json.containsKey( ServiceCoreIF.MsgHeaderSourceSvcID   )) props.put( ServiceCoreIF.MsgHeaderSourceSvcID,   json.getString( ServiceCoreIF.MsgHeaderSourceSvcID   ));
    if( json.containsKey( ServiceCoreIF.MsgHeaderTargetSvcID   )) props.put( ServiceCoreIF.MsgHeaderTargetSvcID,   json.getString( ServiceCoreIF.MsgHeaderTargetSvcID   ));
    if( json.containsKey( ServiceCoreIF.MsgHeaderEventType     )) props.put( ServiceCoreIF.MsgHeaderEventType,     json.getString( ServiceCoreIF.MsgHeaderEventType     ));
    if( json.containsKey( ServiceCoreIF.MsgHeaderCorrelationId )) props.put( ServiceCoreIF.MsgHeaderCorrelationId, json.getString( ServiceCoreIF.MsgHeaderCorrelationId ));
    if( json.containsKey( ServiceCoreIF.MsgHeaderTimeStamp     )) props.put( ServiceCoreIF.MsgHeaderTimeStamp,     json.getString( ServiceCoreIF.MsgHeaderTimeStamp     ));
    if( json.containsKey( ServiceCoreIF.MsgHeaderVersion       )) props.put( ServiceCoreIF.MsgHeaderVersion,       json.getString( ServiceCoreIF.MsgHeaderVersion       ));

    return props;
  }

}
