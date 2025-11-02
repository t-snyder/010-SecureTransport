package acl;


import core.model.ServiceBundle;
import core.model.service.TopicKey;
import core.model.service.TopicPermission;
import core.utils.KeyEpochUtil;
import service.ServiceDilithiumKeyStore;
import service.TopicKeyStore;
import core.model.DilithiumKey;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;

public class ServiceBundleManager
{
  private static final Logger LOGGER = LoggerFactory.getLogger( ServiceBundleManager.class );

  private final Vertx                    vertx;
  private final WorkerExecutor           workerExecutor;
  private final TopicKeyStore            topicKeyStore;
  private final ServiceDilithiumKeyStore dilithiumKeyStore;

  public ServiceBundleManager( Vertx vertx, TopicKeyStore topicKeyStore, ServiceDilithiumKeyStore dilithiumKeyStore )
  {
    this.vertx             = vertx;
    this.topicKeyStore     = topicKeyStore;
    this.dilithiumKeyStore = dilithiumKeyStore;
    this.workerExecutor    = this.vertx.createSharedWorkerExecutor( "bundle-assembler", 4, 360000 );
  }

  public Future<ServiceBundle> generateServiceBundleOnDemand( String serviceId, String updateType, ServicesACLMatrix matrix )
  {
    return workerExecutor.executeBlocking( () -> 
    {
      Instant now      = Instant.now();
      String  version  = String.valueOf( now.toEpochMilli() );
      long    keyEpoch = KeyEpochUtil.epochNumberForInstant( now );
      
      // --- Assemble all maps before ServiceBundle construction ---

      // 1. TopicPermissions
      Map<String, TopicPermission> topicPermissions = new HashMap<>();
      // 2. TopicKeys
      Map<String, Map<String, TopicKey>> topicKeys = new HashMap<>();

      Set<String> topics = matrix.getTopicsForService( serviceId );
      for( String topicFqn : topics )
      {
        Set<String> access = matrix.getServiceTopicAccess( serviceId, topicFqn );
        boolean canProduce = access.contains( "produce" );
        boolean canConsume = access.contains( "consume" );

        Map<String, TopicKey> keyMap = topicKeyStore.getAllValidKeysForTopic( topicFqn );

        topicPermissions.put( topicFqn, new TopicPermission( serviceId, topicFqn, canProduce, canConsume, keyMap ) );
        if( keyMap != null && !keyMap.isEmpty() )
          topicKeys.put( topicFqn, keyMap );
      }

      // Signing Keys (for this service)
      Map<Long, DilithiumKey> signingKeys = dilithiumKeyStore.getAllValidKeysForService( serviceId );

      // 4. Verify Keys (for all services this service can "consume from")
      Map<String, Map<Long, DilithiumKey>> verifyKeys = new HashMap<>();
      Set<String> consumeFromServices = new HashSet<>();

      // If this service has "consume" permissions on a topic, then get all the serviceIds that
      // have produce permissions for that topic.
      for( String topic : topics )
      {
        Set<String> perms = matrix.getServiceTopicAccess( serviceId, topic );
        if( perms.contains( "consume" ) )
        {
          Set<String> producingServices = matrix.getServicesForTopic( topic );
          for( String producerService : producingServices )
          {
            if( !producerService.equals( serviceId ) )
              consumeFromServices.add( producerService );
          }
        }
      }

      // Obtain the public keys for signing verification for each
      for( String producerService : consumeFromServices )
      {
        Map<Long, DilithiumKey> pubKeys = dilithiumKeyStore.getAllValidVerifyKeysForService( producerService );
        verifyKeys.put( producerService, pubKeys );
      }
      
      // Construct the immutable ServiceBundle with all maps:
      return new ServiceBundle( serviceId, version, keyEpoch, updateType, now, "current", signingKeys, verifyKeys, topicKeys, topicPermissions );
    });
  }

  public void close()
  {
    if( workerExecutor != null )
      workerExecutor.close();
  }
}