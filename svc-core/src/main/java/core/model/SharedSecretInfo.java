package core.model;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.PublicKey;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import org.apache.avro.Schema;
import org.apache.avro.generic.GenericData;
import org.apache.avro.generic.GenericDatumReader;
import org.apache.avro.generic.GenericDatumWriter;
import org.apache.avro.generic.GenericRecord;
import org.apache.avro.io.Decoder;
import org.apache.avro.io.DecoderFactory;
import org.apache.avro.io.Encoder;
import org.apache.avro.io.EncoderFactory;
import org.apache.avro.util.Utf8;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.exceptions.AvroTransformException;
import core.utils.AvroSchemaReader;
import core.utils.AvroUtil;
import io.vertx.core.json.JsonObject;

public class SharedSecretInfo implements Serializable 
{
  private static final long serialVersionUID = 1L;
  private static final Logger            LOGGER                = LoggerFactory.getLogger( SharedSecretInfo.class );
  private static final DateTimeFormatter ISO_INSTANT_FORMATTER = DateTimeFormatter.ISO_INSTANT;
 
  // Avro serialization keys
  private static final String KeyId         = "keyId";
  private static final String SourceSvcId   = "sourceSvcId";
  private static final String TargetSvcId   = "targetSvcId";
  private static final String PublicKey     = "publicKey";
  private static final String SharedSecret  = "sharedSecret";
  private static final String CreateTime    = "createTime";
  private static final String ExpiryTime    = "expiryTime";
  
  private static Schema    msgSchema = null;
  private static AvroUtil  avroUtil  = new AvroUtil();

  private String  keyId;           // Unique key identifier (timestamp + random)
  private String  sourceSvcId;     // Initiator
  private String  targetSvcId;     // Responder
  private byte[]  publicKey;       // Public Key used to generate encapsulation
  private byte[]  sharedSecret;    // The shared secret bytes
  private Instant created;         // Creation timestamp
  private Instant expires;         // Expiry timestamp

  public SharedSecretInfo( String  keyId,
                           String  sourceSvcId,
                           String  targetSvcId,
                           byte[]  publicKey,
                           byte[]  sharedSecret,
                           Instant created,
                           Instant expires ) 
  {
    this.keyId        = keyId;
    this.sourceSvcId  = sourceSvcId;
    this.targetSvcId  = targetSvcId;
    this.publicKey    = publicKey;
    this.sharedSecret = sharedSecret;
    this.created      = created;
    this.expires      = expires;
  }

  public String  getKeyId()        { return keyId;        }
  public String  getSourceSvcId()  { return sourceSvcId;  }
  public String  getTargetSvcId()  { return targetSvcId;  }
  public byte[]  getPublicKey()    { return publicKey;    }
  public byte[]  getSharedSecret() { return sharedSecret; }
  public Instant getCreated()      { return created;      }
  public Instant getExpires()      { return expires;      }

/**  
  public JsonObject toJson() {
    JsonObject json = new JsonObject();
    json.put("keyId",        keyId        );
    json.put("sourceSvcId",  sourceSvcId  );
    json.put("targetSvcId",  targetSvcId  );
    json.put("publicKey",    publicKey    );
    json.put("sharedSecret", sharedSecret );
    json.put("created",      created.toString() );
    json.put("expires",      expires.toString() );

    return json;
  }

  public static SharedSecretInfo fromJson(JsonObject json) 
  {
    String keyId        = json.getString( "keyId"        );
    String sourceSvcId  = json.getString( "sourceSvcId"  );
    String targetSvcId  = json.getString( "targetSvcId"  );
    byte[] publicKey    = json.getBinary( "publicKey"    );
    byte[] sharedSecret = json.getBinary( "sharedSecret" );
    String created      = json.getString( "created"      );
    String expires      = json.getString( "expires"      );
 
    return new SharedSecretInfo( keyId, sourceSvcId, targetSvcId, publicKey, sharedSecret, Instant.parse( created ),  Instant.parse( expires ));
  }
*/  
  public static SharedSecretInfo buildSharedSecret( KyberExchangeMessage kyberMsg, PublicKey publicKey, byte[] sharedSecret )
  {
    byte[] publicKeyStr = publicKey.getEncoded();
    
    return new SharedSecretInfo( kyberMsg.getSecretKeyId(), 
                                 kyberMsg.getSourceSvcId(), 
                                 kyberMsg.getTargetSvcId(), 
                                 publicKeyStr, 
                                 sharedSecret, 
                                 kyberMsg.getCreateTime(),
                                 kyberMsg.getExpiryTime() ); 
  }

  /**
   * Serialize for transport using Avro binary format
   * @param purpose - 'transport' or 'signing'
   * @throws Exception 
   */
  public static byte[] serialize( SharedSecretInfo info )
   throws Exception 
  {
    LOGGER.debug("SharedSecretInfo.serialize starting.");
    
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema("SharedSecretInfo"); 

    if(msgSchema == null)
    {
      LOGGER.error("SharedSecretInfo.serialize could not obtain schema = CaBundleMessage");
      throw new Exception("SharedSecretInfo.serialize - Avro schema not found");
    }

    LOGGER.debug("SharedSecretInfo.serialize found msgSchema.");

    try
    {
      ByteArrayOutputStream             out     = new ByteArrayOutputStream();
      Encoder                           encoder = EncoderFactory.get().binaryEncoder(out, null);
      GenericDatumWriter<GenericRecord> writer  = new GenericDatumWriter<GenericRecord>(msgSchema);
      GenericRecord                     theRec  = (GenericRecord) new GenericData.Record(msgSchema);

      if( info.getKeyId()        != null ) theRec.put( KeyId,        new Utf8( info.getKeyId()               ));  
      if( info.getSourceSvcId()  != null ) theRec.put( SourceSvcId,  new Utf8( info.getSourceSvcId()         ));  
      if( info.getTargetSvcId()  != null ) theRec.put( TargetSvcId,  new Utf8( info.getTargetSvcId()         ));  
      if( info.getPublicKey()    != null ) theRec.put( PublicKey,    ByteBuffer.wrap( info.getPublicKey()    )); 
      if( info.getSharedSecret() != null ) theRec.put( SharedSecret, ByteBuffer.wrap( info.getSharedSecret() )); 
      if( info.getCreated()      != null ) theRec.put( CreateTime,   new Utf8( info.getCreated().toString()  ));  
      if( info.getExpires()      != null ) theRec.put( ExpiryTime,   new Utf8( info.getExpires().toString()  )); 
      
      try
      {
        writer.write( theRec, encoder );
        encoder.flush();
      } 
      catch(IOException e)
      {
        String msg = "SharedSecretInfo.serialize - Error = " + e.getMessage();
        LOGGER.error(msg);
        throw new AvroTransformException(msg);
      }
      
      LOGGER.debug("SharedSecretInfo.serialize complete");
    
      return out.toByteArray();
    } 
    catch(Exception e)
    {
      String msg = "SharedSecretInfo.serialize - Error = " + e.getMessage();
      LOGGER.error(msg);
      throw new AvroTransformException(msg);
    }
  }

  /**
   * 
   * @param bytes
   * @param purpose - 'transport' or 'signing'
   * @return
   * @throws Exception
   */
  public static SharedSecretInfo deSerialize( byte[] bytes, String purpose ) 
   throws Exception
  {
    LOGGER.debug("SharedSecretInfo.deSerialize - start");
    
    if(msgSchema == null)
      msgSchema = AvroSchemaReader.getSchema("SharedSecretInfo"); 

    if( msgSchema == null)
    {
      String errMsg = "SharedSecretInfo.deSerialize could not obtain schema = DilithiumKey";
      LOGGER.error(errMsg);
      throw new Exception(errMsg);
    }

    LOGGER.debug("SharedSecretInfo.deSerialize found msgSchema.");

    try
    {
      SharedSecretInfo msg = null;

      GenericDatumReader<GenericRecord> reader      = null;
      ByteArrayInputStream              inputStream = new ByteArrayInputStream(bytes);
      Decoder                           decoder     = DecoderFactory.get().binaryDecoder(inputStream, null);

      reader = new GenericDatumReader<GenericRecord>(msgSchema);
         
       while(true)
       {
         try
         {
           GenericRecord result = reader.read(null, decoder);
 
           String keyId             = avroUtil.getString(    result, KeyId        );
           String sourceSvcId       = avroUtil.getString(    result, SourceSvcId  );
           String targetSvcId       = avroUtil.getString(    result, TargetSvcId  );
           byte[] publicKeyBytes    = avroUtil.getByteArray( result, PublicKey    );
           byte[] sharedSecretBytes = avroUtil.getByteArray( result, SharedSecret );
           String createString      = avroUtil.getString(    result, CreateTime   ); 
           String expiryString      = avroUtil.getString(    result, ExpiryTime   ); 
           
           Instant createTime = Instant.from( ISO_INSTANT_FORMATTER.parse( createString ));
           Instant expiryTime = Instant.from( ISO_INSTANT_FORMATTER.parse( expiryString ));
           
           return new SharedSecretInfo( keyId, sourceSvcId, targetSvcId, publicKeyBytes, sharedSecretBytes, createTime, expiryTime );
         } 
         catch(EOFException eof)
         {
           break;
         }
         catch(Exception ex)
         {
           String errMsg = "SharedSecretInfo deSerialize - Error = " + ex.getMessage();
           LOGGER.error(errMsg); 
           throw new AvroTransformException(errMsg);
         }
       }
    
      LOGGER.debug("SharedSecretInfo deSerialize was successful");

      return msg;
    } 
    catch(Exception e)
    {
      String errMsg = "CaBundleMessage deSerialize - Error = " + e.getMessage();
      LOGGER.error(errMsg);
      throw new AvroTransformException(errMsg);
    }
  } 

}