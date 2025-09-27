package core.model;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.Serializable;

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
 * A secure message container for transporting certificate data between
 * services. This class supports serialization to byte arrays and
 * encryption/decryption.
 */
public class CertificateMessage implements Serializable
{
  private static final long   serialVersionUID = 3844367375910100379L;
  private static final Logger LOGGER           = LoggerFactory.getLogger( CertificateMessage.class );

  private static final String MsgId     = "msgId";
  private static final String TimeStamp = "timestamp";
  private static final String EventType = "eventType";
  private static final String ServiceId = "serviceId";
  private static final String CaCert    = "caCert";
  private static final String TlsCert   = "tlsCert";
  
  private static Schema   msgSchema = null;
  private static AvroUtil avroUtil  = new AvroUtil();

  // Message fields
  private String msgId     = null;
  private long   timestamp = 0;
  private String eventType = null; // INITIAL, ADDED, MODIFIED, DELETED
  private String serviceId = null;
  private String caCert    = null; // Base64 encoded CA certificate
  private String tlsCert   = null; // Base64 encoded TLS certificate

  /**
   * Constructor with event type and certificates
   * 
   * @param eventType  - The type of certificate event
   * @param caCert     - The CA certificate data
   * @param tlsCert    - The TLS certificate data
   * @param secretName - The name of the Kubernetes secret
   * @param namespace  - The Kubernetes namespace
   */
  public CertificateMessage( String msgId, long timestamp, String eventType, String serviceId, String caCert, String tlsCert )
  {
    this.msgId     = msgId;
    this.timestamp = timestamp;
    this.eventType = eventType;
    this.serviceId = serviceId;
    this.caCert    = caCert;
    this.tlsCert   = tlsCert;
  }

  public String getMsgId()     { return msgId;     }
  public long   getTimestamp() { return timestamp; }
  public String getEventType() { return eventType; }    
  public String getServiceId() { return serviceId; }
  public String getCaCert()    { return caCert;    }
  public String getTlsCert()   { return tlsCert;   }

  
  /**
   * Serialize using Avro binary format
   * @throws Exception 
   */
  public static byte[] serialize( CertificateMessage msgObj )
   throws Exception 
  {
    LOGGER.info( "CertificateMessage.serialize starting." );
    
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema( "CertificateMessage" ); 

    if( msgSchema == null )
    {
      LOGGER.error( "CertificateMessage serialize could not obtain schema = CertificateMessage" );
      throw new Exception( "CertificateMessage.serialize - Avro schema not found" );
    }

    LOGGER.info( "CertificateMessage.serialize found msgSchema." );

    try
    {
      ByteArrayOutputStream             out     = new ByteArrayOutputStream();
      Encoder                           encoder = EncoderFactory.get().binaryEncoder( out, null );
      GenericDatumWriter<GenericRecord> writer  = new GenericDatumWriter<GenericRecord>( msgSchema );
      GenericRecord                     actRec = (GenericRecord) new GenericData.Record( msgSchema );

      if( msgObj.getMsgId()     != null ) actRec.put( MsgId,     new Utf8( msgObj.getMsgId()     ));  
      if( msgObj.getTimestamp() > 0     ) actRec.put( TimeStamp,           msgObj.getTimestamp()  );  
      if( msgObj.getEventType() != null ) actRec.put( EventType, new Utf8( msgObj.getEventType() ));  
      if( msgObj.getServiceId() != null ) actRec.put( ServiceId, new Utf8( msgObj.getServiceId() ));  
      if( msgObj.getCaCert()    != null ) actRec.put( CaCert,    new Utf8( msgObj.getCaCert()    ));  
      if( msgObj.getTlsCert()   != null ) actRec.put( TlsCert,   new Utf8( msgObj.getTlsCert()   ));  
      
      try
      {
        writer.write( actRec, encoder );
        encoder.flush();
      } 
      catch( IOException e )
      {
        String msg = "CertificateMessage.serialize - Error = " + e.getMessage();
        LOGGER.error( msg );
        throw new AvroTransformException( msg );
      }
      
      LOGGER.info( "CertificateMessage.serialize complete" );
    
      return out.toByteArray();
    } 
    catch( Exception e )
    {
      String msg = "CertificateMessage.serialize - Error = " + e.getMessage();
      LOGGER.error( msg );
      throw new AvroTransformException( msg );
    }
  }

  public static CertificateMessage deSerialize( byte[] bytes ) 
   throws Exception
  {
    LOGGER.info( "CertificateMessage.deSerialize - start" );
    
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema( "CertificateMessage" ); 

    if( msgSchema == null )
    {
      String errMsg = "CertificateMessage deSerialize could not obtain schema = CertificateMessage";
      LOGGER.error( errMsg );
      throw new Exception( errMsg );
    }

    LOGGER.info( "CertificateMessage deSerialize found msgSchema." );

    try
    {
      CertificateMessage msg = null;

      GenericDatumReader<GenericRecord> reader      = null;
      ByteArrayInputStream              inputStream = new ByteArrayInputStream( bytes );
      Decoder                           decoder     = DecoderFactory.get().binaryDecoder( inputStream, null );

      reader = new GenericDatumReader<GenericRecord>( msgSchema );
         
       while( true )
       {
         try
         {
           GenericRecord result = reader.read( null, decoder );
 
           String msgId     = avroUtil.getString( result, MsgId     );
           long   timestamp = avroUtil.getLong(   result, TimeStamp );
           String eventType = avroUtil.getString( result, EventType );
           String serviceId = avroUtil.getString( result, ServiceId );
           String caCert    = avroUtil.getString( result, CaCert    );
           String tlsCert   = avroUtil.getString( result, TlsCert   );
 
          
           msg = new CertificateMessage( msgId, timestamp, eventType, serviceId, caCert, tlsCert );
         } 
         catch( EOFException eof )
         {
           break;
         }
         catch( Exception ex )
         {
           String errMsg = "CertificateMessage deSerialize - Error = " + ex.getMessage();
           LOGGER.error( errMsg ); 
           throw new AvroTransformException( errMsg );
         }
       }
    
      LOGGER.info( "CertificateMessage deSerialize was successful" );

      return msg;
    } 
    catch( Exception e )
    {
      String errMsg = "CertificateMessage deSerialize - Error = " + e.getMessage();
      LOGGER.error( errMsg );
      throw new AvroTransformException( errMsg);
    }
  }   
}