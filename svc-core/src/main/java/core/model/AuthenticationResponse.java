package core.model;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

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


public class AuthenticationResponse implements _AuthenticationIF
{
  private static final Logger LOGGER = LoggerFactory.getLogger( AuthenticationResponse.class );

  private static Schema   msgSchema = null;
  private static AvroUtil aUtil     = new AvroUtil();

  public AuthenticationResponse()
  {
    
  }

  // Object Attributes
  private String oid                   = null;
  private String userToken             = null;
  private String passwordHash          = null;
  private String identityToken         = null;
  private byte[] identitySymmKey       = null;
  private byte[] identityIVSpec        = null;
  private String authorizationToken    = null;
  private byte[] authorizationSymmKey  = null;
  private byte[] authorizationIVSpec   = null;
  private String accountStatus         = null;
  private String mbrLevelCode          = null;
  
  public String getOid()                  { return oid;                  }
  public String getUserToken()            { return userToken;            }
  public String getPasswordHash()         { return passwordHash;         } 
  public String getIdentityToken()        { return identityToken;        }
  public byte[] getIdentitySymmKey()      { return identitySymmKey;      }
  public byte[] getIdentityIVSpec()       { return identityIVSpec;       }
  public String getAuthorizationToken()   { return authorizationToken;   }
  public byte[] getAuthorizationSymmKey() { return authorizationSymmKey; }
  public byte[] getAuthorizationIVSpec()  { return authorizationIVSpec;  }
  public String getAccountStatus()        { return accountStatus;        }
  public String getMbrLevelCode()         { return mbrLevelCode;         }
  
  public void setOid(                  String oid                  ) { this.oid                  = oid;                  }
  public void setUserToken(            String userToken            ) { this.userToken            = userToken;            }
  public void setPasswordHash(         String passwordHash         ) { this.passwordHash         = passwordHash;         }
  public void setIdentityToken(        String identitytoken        ) { this.identityToken        = identitytoken;        }
  public void setIdentitySymmKey(      byte[] identitySymmKey      ) { this.identitySymmKey      = identitySymmKey;      }
  public void setIdentityIVSpec(       byte[] identityIVSpec       ) { this.identityIVSpec       = identityIVSpec;       }
  public void setAuthorizationToken(   String authorizationToken   ) { this.authorizationToken   = authorizationToken;   }
  public void setAuthorizationSymmKey( byte[] authorizationSymmKey ) { this.authorizationSymmKey = authorizationSymmKey; }
  public void setAuthorizationIVSpec(  byte[] authorizationIVSpec  ) { this.authorizationIVSpec  = authorizationIVSpec;  }
  public void setAccountStatus(        String accountStatus        ) { this.accountStatus        = accountStatus;        }
  public void setMbrLevelCode(         String mbrLevelCode         ) { this.mbrLevelCode         = mbrLevelCode;         }

  
  
  /********************************************************************************************************/
  /**
   * @return
   * @throws Exception 
   */
  public byte[] serialize() 
   throws Exception
  {
    if( LOGGER.isTraceEnabled() )
      LOGGER.trace( "Start AuthenticationResponse.serialize" );

      if( msgSchema == null )
        msgSchema = AvroSchemaReader.getSchema( "AuthenticationResponse" ); 

      if( msgSchema == null )
      {
        LOGGER.error( "AuthenticationResponse serialize could not obtain schema = AuthenticationResponse" );
        throw new Exception( "Avro schema not found" );
      }

    try
    {
      ByteArrayOutputStream             out     = new ByteArrayOutputStream();
      Encoder                           encoder = EncoderFactory.get().binaryEncoder( out, null );
      GenericDatumWriter<GenericRecord> writer  = new GenericDatumWriter<GenericRecord>(  msgSchema );
      GenericRecord                     actRec  = (GenericRecord) new GenericData.Record( msgSchema );

      if( oid                  != null ) actRec.put( AUTHENTICATION_OID,           new Utf8( oid                         ));  
      if( userToken            != null ) actRec.put( AUTHENTICATION_USERTOKEN,     new Utf8( userToken                   ));  
      if( passwordHash         != null ) actRec.put( AUTHENTICATION_PW_HASH,       new Utf8( passwordHash                ));  
      if( identityToken        != null ) actRec.put( AUTHENTICATION_ID_TOKEN,      new Utf8( identityToken               ));  
      if( identitySymmKey      != null ) actRec.put( AUTHENTICATION_ID_SYMM_KEY,   ByteBuffer.wrap( identitySymmKey      ));  
      if( identityIVSpec       != null ) actRec.put( AUTHENTICATION_ID_IVSPEC,     ByteBuffer.wrap( identityIVSpec       ));  
      if( authorizationToken   != null ) actRec.put( AUTHENTICATION_AUTH_TOKEN,    new Utf8( authorizationToken          ));  
      if( authorizationSymmKey != null ) actRec.put( AUTHENTICATION_AUTH_SYMM_KEY, ByteBuffer.wrap( authorizationSymmKey ));  
      if( authorizationIVSpec  != null ) actRec.put( AUTHENTICATION_AUTH_IVSPEC,   ByteBuffer.wrap( authorizationIVSpec  ));  
      if( accountStatus        != null ) actRec.put( AUTHENTICATION_STATUS,        new Utf8( accountStatus               ));  
      if( mbrLevelCode         != null ) actRec.put( MEMBER_LEVEL_CODE,            new Utf8( mbrLevelCode                ));  
      
      try
      {
        writer.write( actRec, encoder );
        encoder.flush();
      } catch( IOException e )
        {
          String msg = "Error serializing AuthorizationResponse. Error = " + e.getMessage();
          LOGGER.error( msg );
          throw new AvroTransformException( msg );
        }

      LOGGER.trace( "Completed AuthenticationReponse.marshall" );

      return out.toByteArray();
    } 
    catch( Exception e )
    {
      String errMsg = "Error serializing AuthenticationResponse. Error = " + e.getMessage();
      LOGGER.error( errMsg );
      throw new AvroTransformException( errMsg );
    }
  }
  

  
  /********************************************************************************************************/
  /**
   * deserialize byte[] to Object representation managing different versions of the avro schema.
   * 
   * @return
   * @throws Exception 
   */
  public static AuthenticationResponse deserialize( byte[] bytes ) 
    throws Exception
  {
    if( LOGGER.isTraceEnabled() )
      LOGGER.trace( "Start AuthenticationResponse.serialize" );

    if( msgSchema == null )
        msgSchema = AvroSchemaReader.getSchema( "AuthenticationResponse" ); 

    if( msgSchema == null )
    {
      LOGGER.error( "AuthenticationResponse serialize could not obtain schema = AuthenticationResponse" );
      throw new Exception( "Avro schema not found" );
    }
 
    try
    {
      AuthenticationResponse auth = new AuthenticationResponse();

      GenericDatumReader<GenericRecord> reader      = null;
      ByteArrayInputStream              inputStream = new ByteArrayInputStream( bytes );
      Decoder                           decoder     = DecoderFactory.get().binaryDecoder( inputStream, null );

      reader = new GenericDatumReader<GenericRecord>( msgSchema );
           
      while( true )
      {
        try
        {
          GenericRecord result = reader.read( null, decoder );

          auth.setOid(                  aUtil.getString(    result, AUTHENTICATION_OID           ));
          auth.setUserToken(            aUtil.getString(    result, AUTHENTICATION_USERTOKEN     ));
          auth.setPasswordHash(         aUtil.getString(    result, AUTHENTICATION_PW_HASH       ));
          auth.setIdentityToken(        aUtil.getString(    result, AUTHENTICATION_ID_TOKEN      ));
          auth.setIdentitySymmKey(      aUtil.getByteArray( result, AUTHENTICATION_ID_SYMM_KEY   ));
          auth.setIdentityIVSpec(       aUtil.getByteArray( result, AUTHENTICATION_ID_IVSPEC     ));
          auth.setAuthorizationToken(   aUtil.getString(    result, AUTHENTICATION_AUTH_TOKEN    ));
          auth.setAuthorizationSymmKey( aUtil.getByteArray( result, AUTHENTICATION_AUTH_SYMM_KEY ));
          auth.setAuthorizationIVSpec(  aUtil.getByteArray( result, AUTHENTICATION_AUTH_IVSPEC   ));
          auth.setAccountStatus(        aUtil.getString(    result, AUTHENTICATION_STATUS        ));
          auth.setMbrLevelCode(         aUtil.getString(    result, MEMBER_LEVEL_CODE            ));

          return auth;
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