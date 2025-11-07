package core.transport;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

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
 * A message container with signature information using Avro serialization.
 * The steps for generating a SignedMessage are as follows:
 *   1) serialize the domain message data
 *   2) Create a hash of the serialized msg data. (DilithiumService.sign does both 2 & 3)
 *   3) Sign the hash
 *   4) Obtain the signing key information
 *   5) Obtain the current topic encryption key
 *   6) Encrypt the serialized data into an EncryptedData object (AesGcmHkdfCrypto)
 *   7) Serialize the EncryptedData
 *   8) Build the SignedMessage Object with the serialized byte[] of EncryptedData as the payload.
 *   9) Serialize the SignedMessage Object
 *   
 * The steps for receiving, decrypting and validating the message are essentially the reverse of creation:
 *   1) Deserialize the SignedMessage object
 *   2) Deserialize the EncryptedData into an Object.
 *   3) Obtain the shared secret key to decrypt using the serviceId and encryptKeyId
 *   4) Decrypt the payload  with AesGcmHkdfCrypto using the EncryptedData and shared secret
 *   5) Obtain the signing public key using signerServiceId and signerKeyId
 *   6) Hash the encryptedData.cipherText bytes and verify the signing.
 *   7) Using the Message Type or Payload Type Deserialize the payload (ie. encryptedData.cipherText.
 */
public class SignedMessage implements Serializable
{
  private static final long   serialVersionUID = 1L;
  private static final Logger LOGGER = LoggerFactory.getLogger( SignedMessage.class );

  private static final DateTimeFormatter ISO_INSTANT_FORMATTER = DateTimeFormatter.ISO_INSTANT;

  // Avro field names
  private static final String MESSAGE_ID        = "messageId";
  private static final String MESSAGE_TYPE      = "messageType";    
  private static final String SIGNER_SERVICE_ID = "signerServiceId";
  private static final String SIGNER_KEY_ID     = "signerKeyId";
  private static final String TIMESTAMP         = "timestamp";
  private static final String SIGNATURE         = "signature";
  private static final String TOPIC_NAME        = "topicName";
  private static final String ENCRYPT_KEY_ID    = "encryptKeyId";    
  private static final String PAYLOAD_TYPE      = "payloadType";
  private static final String PAYLOAD           = "payload";

  private static Schema   msgSchema = null;
  private static AvroUtil avroUtil  = new AvroUtil();

  // Message fields
  private String  messageId;
  private String  messageType;
  private String  signerServiceId;
  private Long    signerKeyId;
  private Instant timestamp;
  private byte[]  signature;
  private String  topicName;
  private String  encryptKeyId;
  private String  payloadType;
  private byte[]  payload;

  /**
   * Create a signed message
   */
  public SignedMessage( String messageId, String messageType, String signerServiceId, Long signerKeyId, Instant timestamp, 
                        byte[] signature, String topicName,   String encryptKeyId, String payloadType,  byte[] payload )
  {
    this.messageId       = messageId;
    this.messageType     = messageType;
    this.signerServiceId = signerServiceId;
    this.signerKeyId     = signerKeyId;
    this.timestamp       = timestamp;
    this.signature       = signature;
    this.topicName       = topicName;
    this.encryptKeyId    = encryptKeyId;
    this.payloadType     = payloadType;
    this.payload         = payload;
  }

  // Getters
  public String  getMessageId()       { return messageId;       }
  public String  getMessageType()     { return messageType;     }
  public String  getSignerServiceId() { return signerServiceId; }
  public Long    getSignerKeyId()     { return signerKeyId;     }
  public Instant getTimestamp()       { return timestamp;       }
  public byte[]  getSignature()       { return signature;       }
  public String  getTopicName()       { return topicName;       }
  public String  getEncryptKeyId()    { return encryptKeyId;    } 
  public String  getPayloadType()     { return payloadType;     }
  public byte[]  getPayload()         { return payload;         }

  /**
   * Extract the signature information in format "keyId:base64signature"
  public String getSignatureWithKeyId()
  {
    return signerKeyId + ":" + signature;
  }
   */

  /**
   * Serialize using Avro binary format
   */
  public static byte[] serialize( SignedMessage msgObj ) throws Exception
  {
    LOGGER.debug( "SignedMessage.serialize starting." );

    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema( "SignedMessage" );

    if( msgSchema == null )
    {
      LOGGER.error( "SignedMessage serialize could not obtain schema" );
      throw new Exception( "Avro schema not found for SignedMessage" );
    }

    try
    {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      Encoder encoder = EncoderFactory.get().binaryEncoder( out, null );
      GenericDatumWriter<GenericRecord> writer = new GenericDatumWriter<>( msgSchema );
      GenericRecord record = new GenericData.Record( msgSchema );

      record.put( MESSAGE_ID,        new Utf8( msgObj.getMessageId()       ));
      record.put( MESSAGE_TYPE,      new Utf8( msgObj.getMessageType()     ));
      record.put( SIGNER_SERVICE_ID, new Utf8( msgObj.getSignerServiceId() ));
      record.put( SIGNER_KEY_ID,     msgObj.getSignerKeyId()     );
      record.put( TIMESTAMP,         new Utf8( msgObj.getTimestamp().toString() ));
      record.put( SIGNATURE,         ByteBuffer.wrap( msgObj.getSignature()     ));
      record.put( TOPIC_NAME    ,    new Utf8( msgObj.getTopicName()        ));
      record.put( ENCRYPT_KEY_ID,    new Utf8( msgObj.getEncryptKeyId()    ));
      record.put( PAYLOAD_TYPE,      new Utf8( msgObj.getPayload()  ));
      record.put( PAYLOAD,           ByteBuffer.wrap( msgObj.getPayload()  ));

      writer.write( record, encoder );
      encoder.flush();

      return out.toByteArray();
    } 
    catch( IOException e )
    {
      String msg = "Error serializing SignedMessage: " + e.getMessage();
      LOGGER.error( msg );
      throw new AvroTransformException( msg );
    }
  }

  /**
   * Deserialize from Avro binary format
   */
  public static SignedMessage deserialize( byte[] bytes ) throws Exception
  {
    LOGGER.debug( "SignedMessage.deserialize starting." );

    if( msgSchema == null )
        msgSchema = AvroSchemaReader.getSchema( "SignedMessage" );

    if( msgSchema == null )
    {
      LOGGER.error( "SignedMessage deserialize could not obtain schema" );
      throw new Exception( "Avro schema not found for SignedMessage" );
    }

    try
    {
      SignedMessage result = null;

      GenericDatumReader<GenericRecord> reader = new GenericDatumReader<>( msgSchema );
      ByteArrayInputStream inputStream = new ByteArrayInputStream( bytes );
      Decoder decoder = DecoderFactory.get().binaryDecoder( inputStream, null );

      while( true )
      {
        try
        {
          GenericRecord record = reader.read( null, decoder );

          String messageId       = avroUtil.getString(    record, MESSAGE_ID );
          String messageType     = avroUtil.getString(    record, MESSAGE_TYPE );
          String signerServiceId = avroUtil.getString(    record, SIGNER_SERVICE_ID );
          Long   signerKeyId     = avroUtil.getLong(      record, SIGNER_KEY_ID );
          String timestampStr    = avroUtil.getString(    record, TIMESTAMP );
          byte[] signature       = avroUtil.getByteArray( record, SIGNATURE );
          String topicName       = avroUtil.getString(    record, TOPIC_NAME     );
          String encryptKeyId    = avroUtil.getString(    record, ENCRYPT_KEY_ID );
          String payloadType     = avroUtil.getString(    record, PAYLOAD_TYPE );
          byte[] payload         = avroUtil.getByteArray( record, PAYLOAD );

          Instant timestamp      = Instant.from(ISO_INSTANT_FORMATTER.parse( timestampStr ));

          result = new SignedMessage( messageId, messageType, signerServiceId, signerKeyId,
                                      timestamp, signature,   topicName, encryptKeyId,   payloadType,  payload );
        } 
        catch( EOFException eof )
        {
          break;
        }
      }

      return result;
    } 
    catch( Exception e )
    {
      String msg = "Error deserializing SignedMessage: " + e.getMessage();
      LOGGER.error( msg );
      throw new AvroTransformException( msg );
    }
  }
}