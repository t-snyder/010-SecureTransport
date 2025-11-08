package core.model;


import core.exceptions.AvroTransformException;
import core.model.service.TopicKey;
import core.model.service.TopicPermission;
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
import java.util.*;

/**
 * Avro-only ServiceBundle
 *
 * Fields: - signingKeys: { keyId -> DilithiumKey (Avro bytes) } - verifyKeys: {
 * serviceId -> { keyId -> DilithiumKey (Avro bytes) } } - topicKeys: {
 * topicName -> { keyId -> TopicKey (Avro bytes) } } - topicPermissions: {
 * topicName -> TopicPermissionRecord }
 */
public class ServiceBundle
{
  private static final Logger LOGGER = LoggerFactory.getLogger( ServiceBundle.class );
  private static final DateTimeFormatter ISO_INSTANT_FORMATTER = DateTimeFormatter.ISO_INSTANT;

  private static final String ServiceId        = "serviceId";
  private static final String Version          = "version";
  private static final String KeyEpoch         = "keyEpoch";
  private static final String UpdateType       = "updateType";
  private static final String CreatedAt        = "createdAt";
  private static final String Status           = "status";
  private static final String SigningKeys      = "signingKeys";
  private static final String VerifyKeys       = "verifyKeys";
  private static final String TopicKeys        = "topicKeys";
  private static final String TopicPermissions = "topicPermissions";

  private static Schema msgSchema = null;
  private static final AvroUtil avroUtil = new AvroUtil();

  private final String  serviceId;
  private final String  version;
  private final long    keyEpoch;
  private final String  updateType;
  private final Instant createdAt;
  private final String  status;

  private final Map<Long, DilithiumKey>              signingKeys;
  private final Map<String, Map<Long, DilithiumKey>> verifyKeys;
  private final Map<String, Map<String, TopicKey>>   topicKeys;
  private final Map<String, TopicPermission>         topicPermissions;

  public ServiceBundle( String serviceId, String version, long keyEpoch, String updateType, Instant createdAt, String status )
  {
    this( serviceId, version, keyEpoch, updateType, createdAt, status, new HashMap<>(), new HashMap<>(), new HashMap<>(), new HashMap<>() );
  }

  public ServiceBundle( String serviceId, String version, long keyEpoch, String updateType, Instant createdAt, String status, Map<Long, DilithiumKey> signingKeys, Map<String, Map<Long, DilithiumKey>> verifyKeys,
      Map<String, Map<String, TopicKey>> topicKeys, Map<String, TopicPermission> topicPermissions )
  {
    this.serviceId  = Objects.requireNonNull( serviceId,  "serviceId" );
    this.version    = Objects.requireNonNull( version,    "version" );
    this.keyEpoch   = keyEpoch;
    this.updateType = Objects.requireNonNull( updateType, "updateType" );
    this.createdAt  = Objects.requireNonNull( createdAt,  "createdAt" );
    this.status     = Objects.requireNonNull( status,     "status" );

    this.signingKeys      = signingKeys      != null ? signingKeys      : new HashMap<>();
    this.verifyKeys       = verifyKeys       != null ? verifyKeys       : new HashMap<>();
    this.topicKeys        = topicKeys        != null ? topicKeys        : new HashMap<>();
    this.topicPermissions = topicPermissions != null ? topicPermissions : new HashMap<>();
  }

  // Mutators
  public void putSigningKey( long epoch, DilithiumKey key )
  {
    signingKeys.put( epoch, key );
  }

  public void putVerifyKey( String serviceId, long epoch, DilithiumKey key )
  {
    verifyKeys.computeIfAbsent( serviceId, k -> new HashMap<>() ).put( epoch, key );
  }

  public void putTopicKey( String topicName, String keyId, core.model.service.TopicKey key )
  {
    topicKeys.computeIfAbsent( topicName, t -> new HashMap<>() ).put( keyId, key );
  }

  public void putTopicPermission( TopicPermission perm )
  {
    if( perm != null && perm.getTopicName() != null )
    {
      topicPermissions.put( perm.getTopicName(), perm );
    }
  }

  // Getters
  public String  getServiceId()  { return serviceId;  }
  public String  getVersion()    { return version;    }
  public long    getKeyEpoch()   { return keyEpoch;   }
  public String  getUpdateType() { return updateType; }
  public Instant getCreatedAt()  { return createdAt;  }
  public String  getStatus()     { return status;     }

  public Map<Long, DilithiumKey> getSigningKeys()
  {
    return signingKeys;
  }

  public Map<String, Map<Long, DilithiumKey>> getVerifyKeys()
  {
    return verifyKeys;
  }

  public Map<String, Map<String, core.model.service.TopicKey>> getTopicKeys()
  {
    return topicKeys;
  }

  public Map<String, TopicPermission> getTopicPermissions()
  {
    return topicPermissions;
  }

  // Avro serialization
  public static byte[] serialize( ServiceBundle sb ) throws Exception
  {
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema( "ServiceBundle" );
    if( msgSchema == null )
      throw new Exception( "ServiceBundle.serialize - Avro schema not found" );

    try
    {
      GenericRecord rec = new GenericData.Record( msgSchema );

      rec.put( ServiceId,  new Utf8( sb.getServiceId() ) );
      rec.put( Version,    new Utf8( sb.getVersion() ) );
      rec.put( KeyEpoch,   sb.getKeyEpoch()  );
      rec.put( UpdateType, new Utf8( sb.getUpdateType() ) );
      rec.put( CreatedAt,  new Utf8( sb.getCreatedAt().toString() ) );
      rec.put( Status,     new Utf8( sb.getStatus() ) );

      // signingKeys: map<long, bytes> (Avro of DilithiumKey)
      Map<Long, ByteBuffer> skMap = new HashMap<>();
      for( Map.Entry<Long, DilithiumKey> e : sb.signingKeys.entrySet() )
      {
        byte[] raw = DilithiumKey.serialize( e.getValue(), "transport" );
        skMap.put( e.getKey(), ByteBuffer.wrap( raw ) );
      }
      rec.put( SigningKeys, skMap );

      // verifyKeys: map<string, map<string, bytes>>
      Map<String, Map<Long, ByteBuffer>> vkOuter = new HashMap<>();
      for( Map.Entry<String, Map<Long, DilithiumKey>> svc : sb.verifyKeys.entrySet() )
      {
        Map<Long, ByteBuffer> inner = new HashMap<>();
        for( Map.Entry<Long, DilithiumKey> e : svc.getValue().entrySet() )
        {
          byte[] raw = DilithiumKey.serialize( e.getValue(), "transport" );
          inner.put( e.getKey(), ByteBuffer.wrap( raw ) );
        }
        vkOuter.put( svc.getKey(), inner );
      }
      rec.put( VerifyKeys, vkOuter );

      // topicKeys: map<string, map<string, bytes>> (Avro of TopicKey)
      Map<String, Map<String, ByteBuffer>> tkOuter = new HashMap<>();
      for( Map.Entry<String, Map<String, TopicKey>> byTopic : sb.topicKeys.entrySet() )
      {
        Map<String, ByteBuffer> inner = new HashMap<>();
        Map<String, core.model.service.TopicKey> keys = byTopic.getValue();
        if( keys != null )
        {
          for( Map.Entry<String, TopicKey> e : keys.entrySet() )
          {
            byte[] raw = TopicKey.serialize( e.getValue() );
            inner.put( e.getKey(), ByteBuffer.wrap( raw ) );
          }
        }
        tkOuter.put( byTopic.getKey(), inner );
      }
      rec.put( TopicKeys, tkOuter );

      // topicPermissions: map<string, TopicPermissionRecord>
      Map<String, GenericRecord> tpMap = new HashMap<>();
      Schema tpSchema = msgSchema.getField( TopicPermissions ).schema().getValueType();
      for( Map.Entry<String, TopicPermission> e : sb.topicPermissions.entrySet() )
      {
        GenericRecord tp = new GenericData.Record( tpSchema );
        tp.put( "topicName",         e.getValue().getTopicName() );
        tp.put( "producePermission", e.getValue().getProducePermission() );
        tp.put( "consumePermission", e.getValue().getConsumePermission() );
        tpMap.put( e.getKey(), tp );
      }
      rec.put( TopicPermissions, tpMap );

      ByteArrayOutputStream out = new ByteArrayOutputStream();
      Encoder encoder = EncoderFactory.get().binaryEncoder( out, null );
      @SuppressWarnings( "unchecked" )
      GenericDatumWriter<GenericRecord> writer = new GenericDatumWriter<>( msgSchema );
      writer.write( rec, encoder );
      encoder.flush();
      return out.toByteArray();
    } 
    catch( Exception e )
    {
      String msg = "ServiceBundle.serialize - Error = " + e.getMessage();
      LOGGER.error( msg, e );
      throw new AvroTransformException( msg );
    }
  }

  public static ServiceBundle deSerialize( byte[] bytes ) throws Exception
  {
    if( msgSchema == null )
      msgSchema = AvroSchemaReader.getSchema( "ServiceBundle" );
    if( msgSchema == null )
      throw new Exception( "ServiceBundle.deSerialize - Avro schema not found" );

    try
    {
      ServiceBundle out = null;

      GenericDatumReader<GenericRecord> reader = new GenericDatumReader<>( msgSchema );
      Decoder decoder = DecoderFactory.get().binaryDecoder( new ByteArrayInputStream( bytes ), null );

      while( true )
      {
        try
        {
          GenericRecord rec = reader.read( null, decoder );

          String serviceId  = avroUtil.getString( rec, ServiceId );
          String version    = avroUtil.getString( rec, Version );
          long   keyEpoch   = avroUtil.getLong(   rec, KeyEpoch );
          String updateType = avroUtil.getString( rec, UpdateType );
          String createdStr = avroUtil.getString( rec, CreatedAt );
          String status     = avroUtil.getString( rec, Status );

          Instant createdAt = createdStr != null ? Instant.from( ISO_INSTANT_FORMATTER.parse( createdStr ) ) : Instant.now();

          // signingKeys
          Map<Long, DilithiumKey> signingKeys = new HashMap<>();
          @SuppressWarnings( "unchecked" )
          Map<Utf8, ByteBuffer> skMap = (Map<Utf8, ByteBuffer>)rec.get( SigningKeys );
          if( skMap != null )
          {
            for( Map.Entry<Utf8, ByteBuffer> e : skMap.entrySet() )
            {
              byte[] raw = toArray( e.getValue() );
              DilithiumKey dk = DilithiumKey.deSerialize( raw, "transport" );
              // Convert Utf8 key back to Long
              Long epochKey = Long.parseLong( e.getKey().toString() );
              signingKeys.put( epochKey, dk );
            }
          }
 
       // verifyKeys
          Map<String, Map<Long, DilithiumKey>> verifyKeys = new HashMap<>();
          @SuppressWarnings( "unchecked" )
          Map<Utf8, Map<Utf8, ByteBuffer>> vkOuter = (Map<Utf8, Map<Utf8, ByteBuffer>>)rec.get( VerifyKeys );
          if( vkOuter != null )
          {
            for( Map.Entry<Utf8, Map<Utf8, ByteBuffer>> svc : vkOuter.entrySet() )
            {
              Map<Long, DilithiumKey> inner = new HashMap<>();
              Map<Utf8, ByteBuffer> in = svc.getValue();
              if( in != null )
              {
                for( Map.Entry<Utf8, ByteBuffer> e : in.entrySet() )
                {
                  byte[] raw = toArray( e.getValue() );
                  DilithiumKey dk = DilithiumKey.deSerialize( raw, "transport" );
                  // Convert Utf8 key back to Long
                  Long epochKey = Long.parseLong( e.getKey().toString() );
                  inner.put( epochKey, dk );
                }
              }
              verifyKeys.put( svc.getKey().toString(), inner );
            }
          }
          
          // topicKeys
          Map<String, Map<String, core.model.service.TopicKey>> topicKeys = new HashMap<>();
          @SuppressWarnings( "unchecked" )
          Map<Utf8, Map<Utf8, ByteBuffer>> tkOuter = (Map<Utf8, Map<Utf8, ByteBuffer>>)rec.get( TopicKeys );
          if( tkOuter != null )
          {
            for( Map.Entry<Utf8, Map<Utf8, ByteBuffer>> byTopic : tkOuter.entrySet() )
            {
              Map<String, core.model.service.TopicKey> inner = new HashMap<>();
              Map<Utf8, ByteBuffer> in = byTopic.getValue();
              if( in != null )
              {
                for( Map.Entry<Utf8, ByteBuffer> e : in.entrySet() )
                {
                  byte[] raw = toArray( e.getValue() );
                  core.model.service.TopicKey tk = core.model.service.TopicKey.deSerialize( raw );
                  inner.put( e.getKey().toString(), tk );
                }
              }
              topicKeys.put( byTopic.getKey().toString(), inner );
            }
          }

          // topicPermissions
          Map<String, TopicPermission> topicPermissions = new HashMap<>();
          @SuppressWarnings( "unchecked" )
          Map<Utf8, GenericRecord> tpMap = (Map<Utf8, GenericRecord>)rec.get( TopicPermissions );
          if( tpMap != null )
          {
            for( Map.Entry<Utf8, GenericRecord> e : tpMap.entrySet() )
            {
              GenericRecord tpRec = e.getValue();
              String topicName = avroUtil.getString( tpRec, "topicName" );
              boolean produce = getBoolean( tpRec, "producePermission" );
              boolean consume = getBoolean( tpRec, "consumePermission" );
              TopicPermission tp = new TopicPermission( serviceId, topicName, produce, consume, null );
              topicPermissions.put( e.getKey().toString(), tp );
            }
          }

          out = new ServiceBundle( serviceId, version, keyEpoch, updateType, createdAt, status, signingKeys, verifyKeys, topicKeys, topicPermissions );
        } 
        catch( EOFException eof )
        {
          break;
        }
      }

      return out;
    } 
    catch( Exception e )
    {
      String msg = "ServiceBundle.deSerialize - Error = " + e.getMessage();
      LOGGER.error( msg, e );
      throw new AvroTransformException( msg );
    }
  }

  private static boolean getBoolean( GenericRecord rec, String field )
  {
    Object v = rec.get( field );
    if( v instanceof Boolean b )
      return b;
    if( v == null )
      return false;
    return Boolean.parseBoolean( v.toString() );
  }

  private static byte[] toArray( ByteBuffer bb )
  {
    if( bb == null )
      return null;
    byte[] out = new byte[bb.remaining()];
    bb.duplicate().get( out );
    return out;
  }
}