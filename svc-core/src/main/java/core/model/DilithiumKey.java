package core.model;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.exceptions.AvroTransformException;
import core.service.DilithiumService;
import core.utils.AvroSchemaReader;
import core.utils.AvroUtil;
import io.vertx.core.json.JsonObject;

/**
 * Unified model for Dilithium keys - handles both public-only and full keypairs
 */
public class DilithiumKey
{
  private static final Logger            LOGGER                = LoggerFactory.getLogger( DilithiumKey.class );
  private static final DateTimeFormatter ISO_INSTANT_FORMATTER = DateTimeFormatter.ISO_INSTANT;
 
  // Avro serialization keys
  private static final String KeyId             = "keyId";
  private static final String ServiceId         = "serviceId";
  private static final String PublicKeyBytes    = "publicKeyBytes";
  private static final String PrivateKeyBytes   = "privateKeyBytes";
  private static final String EpochNumber       = "epochNumber";
  private static final String CreateTime        = "createTime";
  private static final String ExpiryTime        = "expiryTime";
  private static final String MetadataKeyId     = "metadataKeyId";
  private static final String MetadataSignature = "metadataSignature";
  
  private static Schema    msgSchema = null;
  private static AvroUtil  avroUtil  = new AvroUtil();

  private final String     keyId;
  private final String     serviceId;
  private final PublicKey  publicKey;
  private final PrivateKey privateKey; // null for public-only keys
  private final long       epochNumber;
  private final Instant    createTime;
  private final Instant    expiryTime;

  // Metadata service authorization
  private String metadataKeyId;
  private byte[] metadataSignature;

  // Constructor for full keypair (signing keys)
  public DilithiumKey( String keyId, String serviceId, KeyPair keyPair, long epochNumber, Instant createTime, Instant expiryTime )
  {
    this.keyId       = keyId;
    this.serviceId   = serviceId;
    this.publicKey   = keyPair.getPublic();
    this.privateKey  = keyPair.getPrivate();
    this.epochNumber = epochNumber;
    this.createTime  = createTime;
    this.expiryTime  = expiryTime;
  }

  // Constructor for public-only key (verification keys)
  public DilithiumKey( String keyId, String serviceId, PublicKey publicKey, long epochNumber, Instant createTime, Instant expiryTime )
  {
    this.keyId       = keyId;
    this.serviceId   = serviceId;
    this.publicKey   = publicKey;
    this.privateKey  = null;
    this.epochNumber = epochNumber;
    this.createTime  = createTime;
    this.expiryTime  = expiryTime;
  }

  // Getters
  public String     getKeyId()       { return keyId;       }
  public String     getServiceId()   { return serviceId;   }
  public PublicKey  getPublicKey()   { return publicKey;   }
  public PrivateKey getPrivateKey()  { return privateKey;  }
  public long       getEpochNumber() { return epochNumber; }
  public Instant    getCreateTime()  { return createTime;  }
  public Instant    getExpiryTime()  { return expiryTime;  }

  // Authorization methods
  public void setMetadataAuthorization( String keyId, byte[] signature )
  {
    this.metadataKeyId     = keyId;
    this.metadataSignature = signature;
  }

  public String getMetadataKeyId()     { return metadataKeyId; }
  public byte[] getMetadataSignature() { return metadataSignature; }


  // Utility methods
  public boolean isAuthorized()
  {
    return metadataKeyId != null && metadataSignature != null;
  }

  public boolean canSign()
  {
    return privateKey != null;
  }

  public boolean isExpired()
  {
    return Instant.now().isAfter( expiryTime );
  }

/**  
  // Serialization support
  public JsonObject toJson()
  {
    JsonObject json = new JsonObject().put( "keyId", keyId )
                                      .put( "serviceId", serviceId )
                                      .put( "publicKey", Base64.getEncoder().encodeToString( publicKey.getEncoded() ) )
                                      .put( "createTime", createTime.toString() )
                                      .put( "expiryTime", expiryTime.toString() );

    if( canSign() )
    {
      json.put( "privateKey", Base64.getEncoder().encodeToString( privateKey.getEncoded() ) );
    }

    if( isAuthorized() )
    {
      json.put( "metadataKeyId", metadataKeyId ).put( "metadataSignature", Base64.getEncoder().encodeToString( metadataSignature ) );
    }

    return json;
  }

  public static DilithiumKey fromJson( JsonObject keyData ) 
  {
    try 
    {
      String keyId       = keyData.getString( "keyId"     );
      String serviceId   = keyData.getString( "serviceId" );
      long   epochNumber = keyData.getLong( "epochNumber" );
      
      // Reconstruct keys
      byte[]     publicKeyBytes = Base64.getDecoder().decode( keyData.getString( "publicKey" ));
      KeyFactory keyFactory     = KeyFactory.getInstance( "DILITHIUM", "BC" );
      PublicKey  publicKey      = keyFactory.generatePublic( new X509EncodedKeySpec( publicKeyBytes ));
        
      PrivateKey privateKey = null;
      if( keyData.containsKey( "privateKey" )) 
      {
        byte[] privateKeyBytes = Base64.getDecoder().decode(keyData.getString("privateKey"));
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
      }
        
      Instant createTime = Instant.parse(keyData.getString("createTime"));
      Instant expiryTime = Instant.parse(keyData.getString("expiryTime"));
        
      DilithiumKey key;
      if( privateKey != null ) 
      { // Signing key
        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        key = new DilithiumKey(keyId, serviceId, keyPair, epochNumber, createTime, expiryTime);
      } 
      else 
      { // Public key
        key = new DilithiumKey(keyId, serviceId, publicKey, epochNumber, createTime, expiryTime);
      }
        
      // Set authorization if present
      if( keyData.containsKey( "metadataKeyId" ) && keyData.containsKey( "metadataSignature" ))
      {
        String metadataKeyId = keyData.getString("metadataKeyId");
        byte[] metadataSignature = Base64.getDecoder().decode(keyData.getString("metadataSignature"));
        key.setMetadataAuthorization(metadataKeyId, metadataSignature);
      }
        
      return key;
    } 
    catch( Exception e ) 
    {
      throw new RuntimeException("Failed to reconstruct DilithiumKey", e);
    }
  }  
*/
  
  /**
   * Serialize for transport using Avro binary format
   * @param purpose - 'transport' or 'signing'
   * @throws Exception 
   */
  public static byte[] serialize( DilithiumKey key, String purpose )
   throws Exception 
  {
    LOGGER.debug("DilithiumKey.serialize starting.");
    
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema("DilithiumKey"); 

    if(msgSchema == null)
    {
      LOGGER.error("DilithiumKey.serialize could not obtain schema = DilithiumKey");
      throw new Exception("DilithiumKey.serialize - Avro schema not found");
    }

    LOGGER.debug("DilithiumKey.serialize found msgSchema.");

    try
    {
      ByteArrayOutputStream             out     = new ByteArrayOutputStream();
      Encoder                           encoder = EncoderFactory.get().binaryEncoder(out, null);
      GenericDatumWriter<GenericRecord> writer  = new GenericDatumWriter<GenericRecord>(msgSchema);
      GenericRecord                     theRec  = (GenericRecord) new GenericData.Record(msgSchema);

      if( key.getKeyId()       != null ) theRec.put( KeyId,           new Utf8( key.getKeyId()                 ));  
      if( key.getServiceId()   != null ) theRec.put( ServiceId,       new Utf8( key.getServiceId()             ));  
      if( key.getPublicKey()   != null ) theRec.put( PublicKeyBytes,  ByteBuffer.wrap( key.getPublicKey().getEncoded()  )); 
      if( key.getPrivateKey()  != null ) theRec.put( PrivateKeyBytes, ByteBuffer.wrap( key.getPrivateKey().getEncoded() )); 
      if( key.getEpochNumber() > 0     ) theRec.put( EpochNumber,     key.getEpochNumber() ); 
      if( key.getCreateTime()  != null ) theRec.put( CreateTime,      new Utf8( key.getCreateTime().toString() ));  
      if( key.getExpiryTime()  != null ) theRec.put( ExpiryTime,      new Utf8( key.getExpiryTime().toString() )); 

      if( !"signing".equals( purpose ) )
      {
        if( key.getMetadataKeyId()     != null ) theRec.put( MetadataKeyId,     new Utf8( key.getMetadataKeyId() ));  
        if( key.getMetadataSignature() != null ) theRec.put( MetadataSignature, ByteBuffer.wrap( key.getMetadataSignature() ));  
      }
     
      try
      {
        writer.write( theRec, encoder );
        encoder.flush();
      } 
      catch(IOException e)
      {
        String msg = "DilithiumKey.serialize - Error = " + e.getMessage();
        LOGGER.error(msg);
        throw new AvroTransformException(msg);
      }
      
      LOGGER.debug("DilithiumKey.serialize complete");
    
      return out.toByteArray();
    } 
    catch(Exception e)
    {
      String msg = "DilithiumKey.serialize - Error = " + e.getMessage();
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
  public static DilithiumKey deSerialize( byte[] bytes, String purpose ) 
   throws Exception
  {
    LOGGER.debug("DilithiumKey.deSerialize - start");
    
    if(msgSchema == null)
      msgSchema = AvroSchemaReader.getSchema("DilithiumKey"); 

    if( msgSchema == null)
    {
      String errMsg = "DilithiumKey.deSerialize could not obtain schema = DilithiumKey";
      LOGGER.error( errMsg );
      throw new Exception(errMsg);
    }

    LOGGER.debug("DilithiumKey.deSerialize found msgSchema.");

    try
    {
      DilithiumKey msg = null;

      GenericDatumReader<GenericRecord> reader      = null;
      ByteArrayInputStream              inputStream = new ByteArrayInputStream(bytes);
      Decoder                           decoder     = DecoderFactory.get().binaryDecoder(inputStream, null);

      reader = new GenericDatumReader<GenericRecord>(msgSchema);
         
       while(true)
       {
         try
         {
           GenericRecord result = reader.read(null, decoder);
 
           String keyId             = avroUtil.getString(    result, KeyId              );
           String serviceId         = avroUtil.getString(    result, ServiceId          );
           byte[] publicKeyBytes    = avroUtil.getByteArray( result, PublicKeyBytes     );
           byte[] privateKeyBytes   = avroUtil.getByteArray( result, PrivateKeyBytes    );
           long   epochNumber       = avroUtil.getLong(      result, EpochNumber        );
           String createString      = avroUtil.getString(    result, CreateTime         ); 
           String expiryString      = avroUtil.getString(    result, ExpiryTime         ); 

           String metadataKeyId     = null;
           byte[] metadataSignature = null;
           
           if( !"signing".equals( purpose ) )
           {
             metadataKeyId     = avroUtil.getString(    result, MetadataKeyId      );
             metadataSignature = avroUtil.getByteArray( result, MetadataSignature  );
           }
                 
           Instant createTime    = Instant.from( ISO_INSTANT_FORMATTER.parse( createString ));
           Instant expiryTime    = Instant.from( ISO_INSTANT_FORMATTER.parse( expiryString ));

           // Reconstruct the keys using BouncyCastle KeyFactory
           PublicKey  publicKey  = null;
           PrivateKey privateKey = null;
           DilithiumPublicKeyParameters pubParams = null;
          
           if( publicKeyBytes != null ) 
           {
             try
             {
               pubParams = new DilithiumPublicKeyParameters( DilithiumParameters.dilithium5, publicKeyBytes);
               publicKey = new DilithiumService.DilithiumPublicKey(pubParams);
             }
             catch( Exception e ) 
             {
               LOGGER.error("Failed to reconstruct public key", e);
               throw e;
             }
           }

           if( privateKeyBytes != null ) 
           {
             try 
             {
                DilithiumPrivateKeyParameters privParams = new DilithiumPrivateKeyParameters( DilithiumParameters.dilithium5, privateKeyBytes, pubParams );
                privateKey = new DilithiumService.DilithiumPrivateKey( privParams );
             } 
             catch( Exception e ) 
             {
               LOGGER.error("Failed to reconstruct private key", e);
               throw e;
             }
           }

           // Create the DilithiumKey object
           if( privateKey != null ) 
           {
             // Full keypair
             KeyPair keyPair = new KeyPair(publicKey, privateKey);
             msg = new DilithiumKey( keyId, serviceId, keyPair, epochNumber, createTime, expiryTime );
           } 
           else 
           {
             // Public-only key
             msg = new DilithiumKey( keyId, serviceId, publicKey, epochNumber, createTime, expiryTime );
           }

           // Set metadata authorization if present
           if( metadataKeyId != null && metadataSignature != null ) 
           {
             msg.setMetadataAuthorization( metadataKeyId, metadataSignature);
           }
  
           LOGGER.debug( "Successfully deserialized DilithiumKey: {}", keyId);
           break; // Exit the loop after successful deserialization
         } 
         catch(EOFException eof)
         {
           LOGGER.debug("Reached end of input stream");
           break;
         }
         catch( Exception ex )
         {
           String errMsg = "DilithiumKey deSerialize - Error = " + ex.getMessage();
           LOGGER.error(errMsg); 
           throw new AvroTransformException(errMsg);
         }
       }
    
      LOGGER.debug("DilithiumKey deSerialize was successful");

      return msg;
    } 
    catch(Exception e)
    {
      String errMsg = "DilithiumKey deSerialize - Error = " + e.getMessage();
      LOGGER.error(errMsg);
      throw new AvroTransformException(errMsg);
    }
  } 
  
}