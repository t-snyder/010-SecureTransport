package core.model;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

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


/**
 * Transport object for kyber key exchange and key rotation
 */
public class KyberExchangeMessage implements Serializable
{
  private static final long   serialVersionUID = 1L;
  private static final Logger LOGGER = LoggerFactory.getLogger( KyberExchangeMessage.class );
  private static final DateTimeFormatter ISO_INSTANT_FORMATTER = DateTimeFormatter.ISO_INSTANT;

  // Avro serialization keys
  private static final String SECRET_KEY_ID   = "secretKeyId";
  private static final String SOURCE_SVC_ID   = "sourceSvcId";
  private static final String TARGET_SVC_ID   = "targetSvcId";
  private static final String EVENT_TYPE      = "eventType";
  private static final String PUBLIC_KEY      = "publicKey";
  private static final String ENCAPSULATION   = "encapsulation";
  private static final String CREATE_TIME     = "createTime";
  private static final String EXPIRY_TIME     = "expiryTime";
  private static final String ADDITIONAL_DATA = "additionalData"; // For encrypted Dilithium key data
  private static final String HAS_IDENTITY    = "hasIdentity";    // Flag indicating identity key is present
  
  // Core data
  private String  secretKeyId    = null;
  private String  sourceSvcId    = null; // Service id of the service sending the message.
  private String  targetSvcId    = null; // Service id of the service to receive the message.
  private String  eventType      = null;
  private byte[]  publicKey      = null;
  private byte[]  encapsulation  = null;
  private Instant createTime     = null;
  private Instant expiryTime     = null;
  private byte[]  additionalData = null; // For encrypted Dilithium key data
  private boolean hasIdentity    = false; // Flag indicating identity key is present
  
  // Transport metadata
  private String messageId = null;
  private String timestamp = null;
  private String version   = "1.0";
  
  private static Schema   msgSchema = null;
  private static AvroUtil avroUtil  = new AvroUtil();
  
   /**
   * Used for exchange request
   * @param svcId
   * @param eventType
   * @param publicKey
   */
  public KyberExchangeMessage( String secretKeyId, String sourceSvcId, String targetSvcId, String eventType, byte[] publicKey, Instant createTime, Instant expiryTime )
  {
    this.secretKeyId = secretKeyId;
    this.sourceSvcId = sourceSvcId;        // Message initiator service id
    this.targetSvcId = targetSvcId;
    this.eventType   = eventType;
    this.publicKey   = publicKey;
    this.createTime  = createTime;
    this.expiryTime  = expiryTime;
    this.messageId   = UUID.randomUUID().toString();
    this.timestamp   = Instant.now().toString();
  }

  /**
   * Used for exchange resposne
   * @param svcId
   * @param eventType
   * @param publicKey
   * @param encapsulation
   */
  public KyberExchangeMessage( String secretKeyId, String sourceSvcId, String targetSvcId, String eventType, byte[] publicKey, byte[] encapsulation, Instant createTime, Instant expiryTime )
  {
    this.secretKeyId   = secretKeyId;
    this.sourceSvcId   = sourceSvcId;        // Client sourcecservice id
    this.targetSvcId   = targetSvcId;
    this.eventType     = eventType;
    this.publicKey     = publicKey;
    this.encapsulation = encapsulation;
    this.createTime    = createTime;
    this.expiryTime    = expiryTime;
    this.messageId     = UUID.randomUUID().toString();
    this.timestamp     = Instant.now().toString();
  }
  
  /**
   * Used for exchange response with service identity key
   */
  public KyberExchangeMessage( String secretKeyId, String sourceSvcId, String targetSvcId, String eventType, 
                               byte[] publicKey, byte[] encapsulation, Instant createTime, Instant expiryTime,
                               byte[] additionalData)
  {
    this( secretKeyId, sourceSvcId, targetSvcId, eventType, publicKey, encapsulation, createTime, expiryTime);
    this.additionalData = additionalData;
  }
 
  public String  getSecretKeyId()   { return secretKeyId;   }
  public String  getSourceSvcId()   { return sourceSvcId;   }
  public String  getTargetSvcId()   { return targetSvcId;   }
  public String  getEventType()     { return eventType;     }
  public byte[]  getPublicKey()     { return publicKey;     }
  public byte[]  getEncapsulation() { return encapsulation; }
  public Instant getCreateTime()    { return createTime;    }
  public Instant getExpiryTime()    { return expiryTime;    }
  public String  getMessageId()     { return messageId;     }
  public String  getTimestamp()     { return timestamp;     }
  public String  getVersion()       { return version;       }

  public byte[]  getAdditionalData() { return additionalData; }
  public void    setAdditionalData(byte[] data) 
  { 
    this.additionalData = data; 
  }
  
  public boolean hasAdditionalData() { return additionalData != null; }
  
  /**
   * Create Pulsar message headers compatible with WatcherMsgHeader
   */
  public PulsarMsgHeader createPulsarHeader() 
  {
    return new PulsarMsgHeader( sourceSvcId, targetSvcId, eventType, messageId, timestamp, version );
  }
  
  /**
   * Serialize using Avro binary format
   * @throws Exception 
   */
  public static byte[] serialize( KyberExchangeMessage msgObj )
   throws Exception 
  {
    LOGGER.debug( "KyberKeyExchangeMessage.serialize starting." );
    
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema( "KyberExchangeMessage" ); 

    if( msgSchema == null )
    {
      LOGGER.error( "KeyExchangeMessage serialize could not obtain schema = KyberExchangeMessage" );
      throw new Exception( "Avro schema not found" );
    }

    LOGGER.debug( "KyberKeyExchangeMessage.serialize found msgSchema." );

    try
    {
      ByteArrayOutputStream             out     = new ByteArrayOutputStream();
      Encoder                           encoder = EncoderFactory.get().binaryEncoder( out, null );
      GenericDatumWriter<GenericRecord> writer  = new GenericDatumWriter<GenericRecord>( msgSchema );
      GenericRecord                     actRec = (GenericRecord) new GenericData.Record( msgSchema );

      if( msgObj.getSecretKeyId()   != null ) actRec.put( SECRET_KEY_ID, new Utf8(        msgObj.getSecretKeyId()    ));  
      if( msgObj.getSourceSvcId()   != null ) actRec.put( SOURCE_SVC_ID, new Utf8(        msgObj.getSourceSvcId()    ));  
      if( msgObj.getTargetSvcId()   != null ) actRec.put( TARGET_SVC_ID, new Utf8(        msgObj.getTargetSvcId()    ));  
      if( msgObj.getEventType()     != null ) actRec.put( EVENT_TYPE,    new Utf8(        msgObj.getEventType()      ));  
      if( msgObj.getPublicKey()     != null ) actRec.put( PUBLIC_KEY,    ByteBuffer.wrap( msgObj.getPublicKey()      ));  
      if( msgObj.getEncapsulation() != null ) actRec.put( ENCAPSULATION, ByteBuffer.wrap( msgObj.getEncapsulation()  ));  
      if( msgObj.getCreateTime()    != null ) actRec.put( CREATE_TIME,   new Utf8( msgObj.getCreateTime().toString() ));  
      if( msgObj.getExpiryTime()    != null ) actRec.put( EXPIRY_TIME,   new Utf8( msgObj.getExpiryTime().toString() ));  
 
      if( msgObj.getAdditionalData() != null ) actRec.put( ADDITIONAL_DATA, ByteBuffer.wrap( msgObj.getAdditionalData() ));

      if( msgObj.getEncapsulation() == null )
      {
        LOGGER.debug( "KyberExchangeMessage.serialize found null encapsulation." );
      }
      
      try
      {
        writer.write( actRec, encoder );
        encoder.flush();
      } 
      catch( IOException e )
      {
        String msg = "Error serializing KyberKeyMessage. Error = " + e.getMessage();
        LOGGER.error( msg );
        throw new AvroTransformException( msg );
      }
      
      LOGGER.debug( "KyberExchangeMessage serialization complete" );
    
      return out.toByteArray();
    } 
    catch( Exception e )
    {
      String msg = "Error serializing KyberKeyMessage. Error = " + e.getMessage();
      LOGGER.error( msg );
      throw new AvroTransformException( msg );
    }
  }

  public static KyberExchangeMessage deSerialize( byte[] bytes ) 
   throws Exception
  {
    LOGGER.debug( "Start KyberExchangeMessage deserialize" );
    
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema( "KyberExchangeMessage" ); 

    if( msgSchema == null )
    {
      LOGGER.error( "KeyExchangeMessage serialize could not obtain schema = KyberExchxchagneMessage" );
      throw new Exception( "Avro schema not found" );
    }

    LOGGER.debug( "KyberKeyExchangeMessage.serialize found msgSchema." );

    try
    {
      KyberExchangeMessage msg = null;

      GenericDatumReader<GenericRecord> reader      = null;
      ByteArrayInputStream              inputStream = new ByteArrayInputStream( bytes );
      Decoder                           decoder     = DecoderFactory.get().binaryDecoder( inputStream, null );

      reader = new GenericDatumReader<GenericRecord>( msgSchema );
         
       while( true )
       {
         try
         {
           GenericRecord result = reader.read( null, decoder );
 
           String  secretKeyId   = avroUtil.getString(    result, SECRET_KEY_ID );
           String  sourceSvcId   = avroUtil.getString(    result, SOURCE_SVC_ID );
           String  targetSvcId   = avroUtil.getString(    result, TARGET_SVC_ID );
           String  eventType     = avroUtil.getString(    result, EVENT_TYPE    );
           byte[]  publicKey     = avroUtil.getByteArray( result, PUBLIC_KEY    );
           byte[]  encapsulation = avroUtil.getByteArray( result, ENCAPSULATION );

           String  createString  = avroUtil.getString(    result, CREATE_TIME   ); 
           Instant createTime    = Instant.from(ISO_INSTANT_FORMATTER.parse( createString ));
           
           String  expiryString  = avroUtil.getString(    result, EXPIRY_TIME   ); 
           Instant expiryTime    = Instant.from(ISO_INSTANT_FORMATTER.parse( expiryString ));
 
           // Read additional data if present
           byte[] additionalData = avroUtil.getByteArray(result, ADDITIONAL_DATA);
          
           // Construct message with additionalData and set hasIdentity
           msg = new KyberExchangeMessage( secretKeyId, sourceSvcId, targetSvcId, eventType, publicKey, encapsulation, createTime, expiryTime, additionalData );
           msg.setAdditionalData( additionalData );
         } 
         catch( EOFException eof )
         {
           break;
         }
         catch( Exception ex )
         {
           String errMsg = "Error deserializing KyberExchangeMessage. Error = " + ex.getMessage();
           LOGGER.error( errMsg ); 
           throw new AvroTransformException( errMsg );
         }
       }
    
      LOGGER.debug( "KyberExchangeMessage deserialize was successful" );

      return msg;
    } 
    catch( Exception e )
    {
      String errMsg = "Error encountered deserializing KyberExchangeMessgae. Error = " + e.getMessage();
      LOGGER.error( errMsg );
      throw new AvroTransformException( errMsg);
    }
  } 
}
