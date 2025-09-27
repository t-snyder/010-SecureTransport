package acl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

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

import core.utils.AvroUtil;

/**
 * Implementation for mapping services to topics and their
 * permissions. This class is strictly for permission mapping and does NOT
 * generate or store keys.
 *
 * Usage: - Populate from config/parser - Use getTopicsForService() and
 * getServiceTopicAccess() to drive ServiceBundleManager, which will retrieve
 * topic keys from TopicKeyStore on a per-topic basis.
 */
public class ServicesACLMatrix
{
  // serviceId -> (topicName -> Set<PermissionType>)
  private final Map<String, Map<String, Set<String>>> serviceTopicPermissions = new ConcurrentHashMap<>();
  // topicName -> Set<serviceId>
  private final Map<String, Set<String>> topicToServices = new ConcurrentHashMap<>();

  private static final     String   SERVICE_TOPIC_PERMISSIONS = "serviceTopicPermissions";
  private static transient Schema   msgSchema = null;
  private static final     AvroUtil avroUtil  = new AvroUtil();

  /**
   * Adds a permission for a service to a topic.
   * 
   * @param serviceId
   *          the service id
   * @param topicName
   *          the topic name
   * @param permissionType
   *          "produce", "consume", etc.
   */
  public void addPermission( String serviceId, String topicName, String permissionType )
  {
    serviceTopicPermissions.computeIfAbsent( serviceId, k -> new HashMap<>() ).computeIfAbsent( topicName, k -> new HashSet<>() ).add( permissionType );

    topicToServices.computeIfAbsent( topicName, k -> new HashSet<>() ).add( serviceId );
  }

  /**
   * Removes a permission for a service from a topic. If the permissionType is
   * the last one, removes the topic entry as well.
   */
  public void removePermission( String serviceId, String topicName, String permissionType )
  {
    Map<String, Set<String>> topicPermissions = serviceTopicPermissions.get( serviceId );
    if( topicPermissions != null )
    {
      Set<String> perms = topicPermissions.get( topicName );
      if( perms != null )
      {
        perms.remove( permissionType );
        if( perms.isEmpty() )
        {
          topicPermissions.remove( topicName );
        }
      }
      if( topicPermissions.isEmpty() )
      {
        serviceTopicPermissions.remove( serviceId );
      }
    }
    // Remove from topicToServices if orphaned
    Set<String> services = topicToServices.get( topicName );
    if( services != null )
    {
      services.remove( serviceId );
      if( services.isEmpty() )
      {
        topicToServices.remove( topicName );
      }
    }
  }

  /**
   * Returns all topics for which the given service has any permission.
   */
  public Set<String> getTopicsForService( String serviceId )
  {
    Map<String, Set<String>> topics = serviceTopicPermissions.get( serviceId );
    return topics != null ? new HashSet<>( topics.keySet() ) : Collections.emptySet();
  }

  /**
   * Returns all services that have any permission to the given topic.
   */
  public Set<String> getServicesForTopic( String topicName )
  {
    Set<String> services = topicToServices.get( topicName );
    return services != null ? new HashSet<>( services ) : Collections.emptySet();
  }

  /**
   * Returns the set of permissions ("produce", "consume", etc.) the service has
   * for a topic.
   */
  public Set<String> getServiceTopicAccess( String serviceId, String topicName )
  {
    Map<String, Set<String>> topics = serviceTopicPermissions.get( serviceId );
    return topics != null && topics.containsKey( topicName ) ? new HashSet<>( topics.get( topicName ) ) : Collections.emptySet();
  }

  /**
   * Returns all service IDs.
   */
  public Set<String> getAllServices()
  {
    return new HashSet<>( serviceTopicPermissions.keySet() );
  }

  /**
   * Returns all topic names.
   */
  public Set<String> getAllTopics()
  {
    return new HashSet<>( topicToServices.keySet() );
  }

  /**
   * Returns true if the service has any permissions defined.
   */
  public boolean hasService( String serviceId )
  {
    return serviceTopicPermissions.containsKey( serviceId );
  }

  /**
   * Returns true if the topic exists in the matrix.
   */
  public boolean hasTopic( String topicName )
  {
    return topicToServices.containsKey( topicName );
  }

  /**
   * Clears all permissions, topics, and services.
   */
  public void clear()
  {
    serviceTopicPermissions.clear();
    topicToServices.clear();
  }

  /**
   * Returns a defensive deep copy of the matrix contents.
   */
  public Map<String, Map<String, Set<String>>> snapshot()
  {
    Map<String, Map<String, Set<String>>> copy = new HashMap<>();
    for( var e : serviceTopicPermissions.entrySet() )
    {
      Map<String, Set<String>> topicsCopy = new HashMap<>();
      for( var t : e.getValue().entrySet() )
      {
        topicsCopy.put( t.getKey(), new HashSet<>( t.getValue() ) );
      }
      copy.put( e.getKey(), topicsCopy );
    }
    return copy;
  }
  
  // ==================== Avro Serialization Methods ============================= //

  /**
   * Serialize the ACL matrix to Avro binary format.
   */
  public static byte[] serialize( ServicesACLMatrix matrix ) 
    throws Exception
  {
    if (msgSchema == null)
    {
      msgSchema = core.utils.AvroSchemaReader.getSchema("ServicesACLMatrix");
    }
    if (msgSchema == null)
    {
      throw new Exception("ServicesACLMatrix.serialize - Avro schema not found");
    }

    try
    {
      ByteArrayOutputStream             out     = new ByteArrayOutputStream();
      Encoder                           encoder = EncoderFactory.get().binaryEncoder(out, null);
      GenericDatumWriter<GenericRecord> writer  = new GenericDatumWriter<GenericRecord>(msgSchema);
      GenericRecord                     rec     = (GenericRecord) new GenericData.Record(msgSchema);

      // Build the serviceTopicPermissions map field
      Map<String, Map<String, Set<String>>> stp = matrix.snapshot();

      Map<Utf8, Map<Utf8, List<Utf8>>> avroMap = new HashMap<>();
      for (Map.Entry<String, Map<String, Set<String>>> serviceEntry : stp.entrySet())
      {
        Utf8 serviceIdUtf8 = new Utf8(serviceEntry.getKey());
        Map<Utf8, List<Utf8>> topicMap = new HashMap<>();
        for (Map.Entry<String, Set<String>> topicEntry : serviceEntry.getValue().entrySet())
        {
          Utf8 topicNameUtf8 = new Utf8(topicEntry.getKey());
          List<Utf8> permsList = new ArrayList<>();
          for (String perm : topicEntry.getValue())
          {
            permsList.add(new Utf8(perm));
          }
          topicMap.put(topicNameUtf8, permsList);
        }
        avroMap.put(serviceIdUtf8, topicMap);
      }

      rec.put( SERVICE_TOPIC_PERMISSIONS, avroMap );

      writer.write(rec, encoder);
      encoder.flush();
      return out.toByteArray();
    }
    catch (IOException e)
    {
      throw new RuntimeException("ServicesACLMatrix.serialize - Error = " + e.getMessage(), e);
    }
  }

  /**
   * Deserialize from Avro binary format into a new ServicesACLMatrix.
   */
  public static ServicesACLMatrix deSerialize(byte[] bytes) throws Exception
  {
    if (msgSchema == null)
    {
      msgSchema = core.utils.AvroSchemaReader.getSchema("ServicesACLMatrix");
    }
    if (msgSchema == null)
    {
      throw new Exception("ServicesACLMatrix.deSerialize - Avro schema not found");
    }

    try
    {
      ServicesACLMatrix matrix = new ServicesACLMatrix();

      GenericDatumReader<GenericRecord> reader = new GenericDatumReader<>(msgSchema);
      ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
      Decoder decoder = DecoderFactory.get().binaryDecoder(inputStream, null);

      // Only one record
      GenericRecord rec = reader.read(null, decoder);

      @SuppressWarnings("unchecked")
      Map<Utf8, Map<Utf8, List<Utf8>>> avroMap =
        (Map<Utf8, Map<Utf8, List<Utf8>>>) rec.get(SERVICE_TOPIC_PERMISSIONS);

      if (avroMap != null)
      {
        for (Map.Entry<Utf8, Map<Utf8, List<Utf8>>> serviceEntry : avroMap.entrySet())
        {
          String serviceId = serviceEntry.getKey().toString();
          Map<Utf8, List<Utf8>> topicMap = serviceEntry.getValue();
          for (Map.Entry<Utf8, List<Utf8>> topicEntry : topicMap.entrySet())
          {
            String topicName = topicEntry.getKey().toString();
            List<Utf8> permsList = topicEntry.getValue();
            for (Utf8 permUtf8 : permsList)
            {
              String perm = permUtf8.toString();
              matrix.addPermission(serviceId, topicName, perm);
            }
          }
        }
      }
      return matrix;
    }
    catch( IOException e )
    {
      throw new RuntimeException("ServicesACLMatrix.deSerialize - Error = " + e.getMessage(), e);
    }
  }
}