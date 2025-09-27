package core.model;

import core.exceptions.AvroTransformException;
import core.utils.AvroSchemaReader;
import core.utils.AvroUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.Serializable;
//import java.nio.charset.StandardCharsets;
import java.time.Instant;

//import java.security.KeyFactory;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.Signature;

//import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.X509EncodedKeySpec;

//import java.util.Base64;

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



/**
 * A secure message container for transporting CA bundle data during rotation.
 * This class supports serialization to byte arrays using Avro.
 */
public class CaBundle implements Serializable
{
  private static final long   serialVersionUID    = 2563891234570900341L;
  private static final Logger LOGGER              = LoggerFactory.getLogger( CaBundle.class );

  private static final String ServerId      = "serverId";
  private static final String TimeStamp     = "timestamp";
  private static final String CaEpochNumber = "caEpochNumber";
  private static final String EventType     = "eventType";
  private static final String CaBundle      = "caBundle";
  private static final String CaVersion     = "caVersion";
  
  private static Schema   msgSchema = null;
  private static AvroUtil avroUtil  = new AvroUtil();

  private String  serverId      = null;
  private Instant timestamp     = null;
  private long    caEpochNumber = 0;
  private String  eventType     = null; // CA_ROTATION
  private String  caBundle      = null; // Base64 encoded CA bundle
  private String  caVersion     = null;

  
  /**
   * Constructor with caBundle data fields used for signing message and transport
   * 
   * @param serverId  - 'pulsar', 'vault', 'scylladb', etc.
   * @param timestamp - Creation timestamp
   * @parm  caEpochNumber - CA rotation epoch
   * @param eventType - Type of event (e.g., CA_ROTATION)
   * @param caBundle  - Base64 encoded CA bundle content
   * @param caVersion - CA bundle version identifier
   */
  public CaBundle( String serverId, Instant timestamp, long caEpochNumber, String eventType, 
                   String caBundle, String caVersion )
  {
    this.serverId       = serverId;
    this.timestamp      = timestamp;
    this.caEpochNumber  = caEpochNumber;
    this.eventType      = eventType;
    this.caBundle       = caBundle;
    this.caVersion      = caVersion;
  }

  public String  getServerId()      { return serverId;      }  
  public Instant getTimestamp()     { return timestamp;     }
  public long    getCaEpochNumber() { return caEpochNumber; }
  public String  getEventType()     { return eventType;     }      
  public String  getCaBundle()      { return caBundle;      }
  public String  getCaVersion()     { return caVersion;     }
  
  /**
   * Serialize using Avro binary format
   * @throws Exception 
   */
  public static byte[] serialize( CaBundle msgObj )
   throws Exception 
  {
    LOGGER.info("CaBundle.serialize starting.");
    
    if( msgSchema == null )
        msgSchema = AvroSchemaReader.getSchema("CaBundle"); 

    if(msgSchema == null)
    {
      LOGGER.error("CaBundle serialize could not obtain schema = CaBundle");
      throw new Exception("CaBundle.serialize - Avro schema not found");
    }

    LOGGER.info("CaBundle.serialize found msgSchema.");

    try
    {
      ByteArrayOutputStream             out     = new ByteArrayOutputStream();
      Encoder                           encoder = EncoderFactory.get().binaryEncoder(out, null);
      GenericDatumWriter<GenericRecord> writer  = new GenericDatumWriter<GenericRecord>(msgSchema);
      GenericRecord                     actRec  = (GenericRecord) new GenericData.Record(msgSchema);

      if( msgObj.getServerId()     != null ) actRec.put( ServerId,      new Utf8( msgObj.getServerId()     ));  
      if( msgObj.getTimestamp()    != null ) actRec.put( TimeStamp,     new Utf8( msgObj.getTimestamp().toString() ));  
      if( msgObj.getCaEpochNumber() > 0    ) actRec.put( CaEpochNumber,           msgObj.getCaEpochNumber() );  
      if( msgObj.getEventType()    != null ) actRec.put( EventType,     new Utf8( msgObj.getEventType() ));  
      if( msgObj.getCaBundle()     != null ) actRec.put( CaBundle,      new Utf8( msgObj.getCaBundle()  ));  
      if( msgObj.getCaVersion()    != null ) actRec.put( CaVersion,     new Utf8( msgObj.getCaVersion() ));  
      
      try
      {
        writer.write(actRec, encoder);
        encoder.flush();
      } 
      catch(IOException e)
      {
        String msg = "CaBundle.serialize - Error = " + e.getMessage();
        LOGGER.error(msg);
        throw new AvroTransformException(msg);
      }
      
      LOGGER.info("CaBundle.serialize complete");
    
      return out.toByteArray();
    } 
    catch(Exception e)
    {
      String msg = "CaBundle.serialize - Error = " + e.getMessage();
      LOGGER.error(msg);
      throw new AvroTransformException(msg);
    }
  }

  public static CaBundle deSerialize( byte[] bytes) 
   throws Exception
  {
    LOGGER.info("CaBundle.deSerialize - start");
       
    if(msgSchema == null)
       msgSchema = AvroSchemaReader.getSchema("CaBundle"); 

    if( msgSchema == null)
    {
      String errMsg = "CaBundle deSerialize could not obtain schema = CaBundle";
      LOGGER.error(errMsg);
      throw new Exception(errMsg);
    }

    LOGGER.info("CaBundle deSerialize found msgSchema.");

    try
    {
      CaBundle msg = null;

      GenericDatumReader<GenericRecord> reader      = null;
      ByteArrayInputStream              inputStream = new ByteArrayInputStream(bytes);
      Decoder                           decoder     = DecoderFactory.get().binaryDecoder(inputStream, null);

      reader = new GenericDatumReader<GenericRecord>(msgSchema);
            
      while(true)
      {
        try
        {
          GenericRecord result = reader.read(null, decoder);
    
          String serverId      = avroUtil.getString( result, ServerId );
          String timestampStr  = avroUtil.getString( result, TimeStamp );
          long   caEpochNumber = avroUtil.getLong(   result, CaEpochNumber );
          String eventType     = avroUtil.getString( result, EventType );
          String caBundle      = avroUtil.getString( result, CaBundle  );
          String caVersion     = avroUtil.getString( result, CaVersion );
   
          Instant timestamp = Instant.parse( timestampStr );
          msg = new CaBundle( serverId, timestamp, caEpochNumber, eventType,
                              caBundle, caVersion );
        } 
        catch( EOFException eof )
        {
          break;
        }
        catch( Exception ex )
        {
          String errMsg = "CaBundle deSerialize - Error = " + ex.getMessage();
          LOGGER.error(errMsg); 
          throw new AvroTransformException(errMsg);
        }
      }
       
      LOGGER.info("CaBundle deSerialize was successful");

      return msg;
    } 
    catch(Exception e)
    {
      String errMsg = "CaBundle deSerialize - Error = " + e.getMessage();
      LOGGER.error(errMsg);
      throw new AvroTransformException(errMsg);
    }
  } 
  
}