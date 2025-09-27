package core.model;


import org.apache.avro.Schema;
import org.apache.avro.generic.GenericData;
import org.apache.avro.generic.GenericRecord;
import org.apache.avro.io.BinaryEncoder;
import org.apache.avro.io.EncoderFactory;
import org.apache.avro.util.Utf8;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.exceptions.AvroTransformException;
import core.utils.AvroSchemaReader;
import core.utils.AvroUtil;

import org.apache.avro.io.DatumWriter;
import org.apache.avro.io.DecoderFactory;
import org.apache.avro.io.Encoder;
import org.apache.avro.io.Decoder;
import org.apache.avro.io.DatumReader;
import org.apache.avro.generic.GenericDatumReader;
import org.apache.avro.generic.GenericDatumWriter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Value object for AuthenticationRequest with Avro serialization.
 */
public class AuthenticationRequest
{
  private static final Logger LOGGER = LoggerFactory.getLogger( AuthenticationRequest.class );

  private static final String UserId  = "userId";
  private static final String PwdHash = "pwdHash";
  private static final String Otp     = "otp";
  
  private String userId;
  private String pwdHash;
  private String otp;
  
  private static Schema   msgSchema = null;
  private static AvroUtil avroUtil  = new AvroUtil();


  public AuthenticationRequest( String userId, String pwdHash, String otp )
  {
    this.userId  = userId;
    this.pwdHash = pwdHash;
    this.otp     = otp;
  }

  // Getters
  public String getUserId()  { return userId;  }
  public String getPwdHash() { return pwdHash; }
  public String getOtp()     { return otp;     }

  /**
   * Serialize this object to Avro binary form.
   */
  public byte[] serialize()
   throws Exception
  {
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema( "AuthenticationRequest" ); 

    if( msgSchema == null )
    {
      LOGGER.error( "AuthenticationRequest serialize could not obtain schema = AuthenticationRequest" );
      throw new Exception( "Avro schema not found" );
    }

    try
    {
      ByteArrayOutputStream             out     = new ByteArrayOutputStream();
      Encoder                           encoder = EncoderFactory.get().binaryEncoder( out, null );
      GenericDatumWriter<GenericRecord> writer  = new GenericDatumWriter<GenericRecord>( msgSchema );
      GenericRecord                     actRec = (GenericRecord) new GenericData.Record( msgSchema );

      if( getUserId()  != null ) actRec.put( UserId,  new Utf8( getUserId()  ));  
      if( getPwdHash() != null ) actRec.put( PwdHash, new Utf8( getPwdHash() ));  
      if( getOtp()     != null ) actRec.put( Otp,     new Utf8( getOtp()     ));  
 
      try
      {
        writer.write( actRec, encoder );
        encoder.flush();
      } 
      catch( IOException e )
      {
        String msg = "Error serializing AuthenticationRequest. Error = " + e.getMessage();
        LOGGER.error( msg );
        throw new AvroTransformException( msg );
      }
      
      return out.toByteArray();
    }
    catch( Exception e )
    {
      throw new RuntimeException( "Avro serialization failed", e );
    }
  }

  /**
   * Deserialize Avro binary form into an AuthenticationRequest object.
   */
  public static AuthenticationRequest deserialize( byte[] bytes )
    throws Exception
  {
    
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema( "AuthenticationRequest" ); 

    if( msgSchema == null )
    {
      LOGGER.error( "AuthenticationRequest serialize could not obtain schema = AuthenticationRequest" );
      throw new Exception( "Avro schema not found" );
    }

    try
    {
      AuthenticationRequest request = null;

      GenericDatumReader<GenericRecord> reader      = null;
      ByteArrayInputStream              inputStream = new ByteArrayInputStream( bytes );
      Decoder                           decoder     = DecoderFactory.get().binaryDecoder( inputStream, null );

      reader = new GenericDatumReader<GenericRecord>( msgSchema );
         
       while( true )
       {
         try
         {
           GenericRecord result = reader.read( null, decoder );

           String userId       = avroUtil.getString( result, UserId  );
           String passwordHash = avroUtil.getString( result, PwdHash );
           String otp          = avroUtil.getString( result, Otp     );

           return new AuthenticationRequest( userId, passwordHash, otp );
         } 
         catch( Exception e ) 
         {
           // Older message format may not have these fields
           LOGGER.debug("Message doesn't contain identity fields: {}", e.getMessage());
         }
       } 
    } 
    catch( Exception e )
    {
      throw new RuntimeException( "Avro deserialization failed", e );
    }
  }
}