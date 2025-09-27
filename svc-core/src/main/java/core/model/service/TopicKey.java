package core.model.service;


import core.exceptions.AvroTransformException;
import core.utils.AvroSchemaReader;
import core.utils.AvroUtil;

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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Topic encryption key with optional rotation role attribute (e.g., current,
 * next, legacy). Avro-only; keyData bytes Base64-encoded in Avro 'bytes' field
 * (pattern aligned with DilithiumKey).
 */
public class TopicKey
{
  private static final Logger LOGGER = LoggerFactory.getLogger( TopicKey.class );
  private static final DateTimeFormatter ISO_INSTANT_FORMATTER = DateTimeFormatter.ISO_INSTANT;

  public static final String AES_ALGORITHM = "AES-256";

  // Avro field names
  private static final String KeyId       = "keyId";
  private static final String TopicName   = "topicName";
  private static final String EpochNumber = "epochNumber";
  private static final String Algorithm   = "algorithm";
  private static final String KeyData     = "keyData";
  private static final String CreatedTime = "createdTime";
  private static final String ExpiryTime  = "expiryTime";
  private static final String Role        = "role";

  private static Schema   msgSchema = null;
  private static AvroUtil avroUtil  = new AvroUtil();

  private final String  keyId;
  private final String  topicName;
  private final long    epochNumber;
  private final String  algorithm;
  private final byte[]  keyData;
  private final Instant createdTime;
  private final Instant expiryTime;
  private final String  role; // optional

  public TopicKey( String keyId, String topicName, long epochNumber, String algorithm, byte[] keyData, Instant createdTime, Instant expiryTime )
  {
    this( keyId, topicName, epochNumber, algorithm, keyData, createdTime, expiryTime, null );
  }

  public TopicKey( String keyId, String topicName, long epochNumber, String algorithm, byte[] keyData, Instant createdTime, Instant expiryTime, String role )
  {
    this.keyId       = Objects.requireNonNull( keyId,       "Key ID cannot be null" );
    this.topicName   = Objects.requireNonNull( topicName,   "Topic name cannot be null" );
    this.epochNumber = Objects.requireNonNull( epochNumber, "EpochNumber cannot be null" );
    this.algorithm   = Objects.requireNonNull( algorithm,   "Algorithm cannot be null" );
    this.keyData     = Objects.requireNonNull( keyData,     "Key data cannot be null" ).clone();
    this.createdTime = Objects.requireNonNull( createdTime, "Created time cannot be null" );
    this.expiryTime  = Objects.requireNonNull( expiryTime,  "Expiry time cannot be null" );
    this.role = role;

    if( expiryTime.isBefore( createdTime ) )
      throw new IllegalArgumentException( "Expiry time cannot be before created time" );
  }

  // Getters
  public String  getKeyId()       { return keyId;           }
  public String  getTopicName()   { return topicName;       }
  public long    getEpochNumber() { return epochNumber;     }
  public String  getAlgorithm()   { return algorithm;       }
  public byte[]  getKeyData()     { return keyData.clone(); }
  public Instant getCreatedTime() { return createdTime;     }
  public Instant getExpiryTime()  { return expiryTime;      }
  public String  getRole()        { return role;            }

  // Utility methods
  public boolean isExpired()
  {
    return Instant.now().isAfter( expiryTime );
  }

  public boolean isValid()
  {
    return !isExpired();
  }

  // Avro Serialization
  public static byte[] serialize( TopicKey key ) throws Exception
  {
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema( "TopicKey" );

    if( msgSchema == null )
      throw new Exception( "TopicKey.serialize - Avro schema not found" );

    try
    {
      GenericRecord rec = new GenericData.Record( msgSchema );

      if( key.getKeyId()       != null ) rec.put( KeyId,       new Utf8( key.getKeyId()                 ));  
      if( key.getTopicName()   != null ) rec.put( TopicName,   new Utf8( key.getTopicName() ) );
      if( key.getEpochNumber() > 0     ) rec.put( EpochNumber, key.getEpochNumber()           );
      if( key.getAlgorithm()   != null ) rec.put( Algorithm,   new Utf8( key.getAlgorithm() ) );
      if( key.getKeyData()     != null ) rec.put( KeyData,     ByteBuffer.wrap( Base64.getEncoder().encode( key.getKeyData() ) ) );
      if( key.getCreatedTime() != null ) rec.put( CreatedTime, new Utf8( key.getCreatedTime().toString() ) );
      if( key.getExpiryTime()  != null ) rec.put( ExpiryTime,  new Utf8( key.getExpiryTime().toString() ) );
      if( key.getRole()        != null ) rec.put( Role,        new Utf8( key.getRole() ) );

      ByteArrayOutputStream out = new ByteArrayOutputStream();
      Encoder enc = EncoderFactory.get().binaryEncoder( out, null );
      GenericDatumWriter<GenericRecord> writer = new GenericDatumWriter<>( msgSchema );
      writer.write( rec, enc );
      enc.flush();

      return out.toByteArray();
    } catch( Exception e )
    {
      throw new AvroTransformException( "TopicKey.serialize - " + e.getMessage() );
    }
  }

  public static TopicKey deSerialize( byte[] bytes ) throws Exception
  {
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema( "TopicKey" );

    if( msgSchema == null )
      throw new Exception( "TopicKey.deSerialize - Avro schema not found" );

    try
    {
      TopicKey result = null;

      GenericDatumReader<GenericRecord> reader = new GenericDatumReader<>( msgSchema );
      Decoder decoder = DecoderFactory.get().binaryDecoder( new ByteArrayInputStream( bytes ), null );

      while( true )
      {
        try
        {
          GenericRecord rec = reader.read( null, decoder );

          String keyId       = avroUtil.getString(    rec, KeyId );
          String topicName   = avroUtil.getString(    rec, TopicName );
          long   epochNumber = avroUtil.getLong(      rec, EpochNumber );
          String algorithm   = avroUtil.getString(    rec, Algorithm );
          byte[] keyDataB64  = avroUtil.getByteArray( rec, KeyData );
          String createdStr  = avroUtil.getString(    rec, CreatedTime );
          String expiryStr   = avroUtil.getString(    rec, ExpiryTime );
          String roleStr     = avroUtil.getString(    rec, Role );

          Instant created = createdStr != null ? Instant.from( ISO_INSTANT_FORMATTER.parse( createdStr ) ) : Instant.now();
          Instant expiry = expiryStr != null ? Instant.from( ISO_INSTANT_FORMATTER.parse( expiryStr ) ) : created;

          byte[] keyData = keyDataB64 != null ? Base64.getDecoder().decode( keyDataB64 ) : new byte[0];

          result = new TopicKey( keyId, topicName, epochNumber, algorithm, keyData, created, expiry, roleStr );
        } 
        catch( EOFException eof )
        {
          break;
        }
      }

      return result;
    } catch( Exception e )
    {
      throw new AvroTransformException( "TopicKey.deSerialize - " + e.getMessage() );
    }
  }

  @Override
  public boolean equals( Object obj )
  {
    if( this == obj )
      return true;
    if( obj == null || getClass() != obj.getClass() )
      return false;

    TopicKey that = (TopicKey)obj;
    return Objects.equals( keyId, that.keyId ) && Objects.equals( topicName, that.topicName ) && Objects.equals( algorithm, that.algorithm ) && Arrays.equals( keyData, that.keyData ) && Objects.equals( createdTime, that.createdTime )
        && Objects.equals( expiryTime, that.expiryTime ) && Objects.equals( role, that.role );
  }

  @Override
  public int hashCode()
  {
    return Objects.hash( keyId, topicName, algorithm, Arrays.hashCode( keyData ), createdTime, expiryTime, role );
  }

  @Override
  public String toString()
  {
    return String.format( "TopicKey{keyId='%s', topicName='%s', algorithm='%s', role='%s', created=%s, expires=%s}", keyId, topicName, algorithm, role, createdTime, expiryTime );
  }

  public void clearKeyData()
  {
    Arrays.fill( keyData, (byte)0 );
  }
}