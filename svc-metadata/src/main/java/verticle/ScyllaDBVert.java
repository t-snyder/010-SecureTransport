package verticle;


import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.PreparedStatement;
import com.datastax.oss.driver.api.core.cql.ResultSet;
import com.datastax.oss.driver.api.core.cql.Row;

import core.exceptions.NotFoundException;
//import helper.SSLContextBuilder;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class ScyllaDBVert extends AbstractVerticle
{
  private static final Logger logger = LoggerFactory.getLogger( ScyllaDBVert.class );

  private static final String KEYSPACE = "metadata_keyspace";
  private static final String TABLE    = "metadata";

  private static final String CreateKeySpace  = "CREATE KEYSPACE IF NOT EXISTS " + KEYSPACE + " WITH REPLICATION = { 'class': 'SimpleStrategy', 'replication_factor': 1 }";
  private static final String UseKeySpace     = "USE " + KEYSPACE;
  private static final String CreateTable     = "CREATE TABLE IF NOT EXISTS " + TABLE + " (" + "id UUID PRIMARY KEY, " + "name TEXT, " + "type TEXT, " + "data TEXT, " + "created_at TIMESTAMP, " + "updated_at TIMESTAMP" + ")" ; 

  private static final String InsertStatement     = "INSERT INTO " + TABLE + " (id, name, type, data, created_at, updated_at) " + "VALUES (?, ?, ?, ?, toTimestamp(now()), toTimestamp(now()))";  
  private static final String SelectByIdStatement = "SELECT * FROM " + TABLE + " WHERE id = ?";
  private static final String SelectAllStatement  = "SELECT * FROM " + TABLE; 
  private static final String DeleteByIdStatement = "DELETE FROM " + TABLE + " WHERE id = ?";
  private static final String UpdateStatement     = "UPDATE " + TABLE + " SET name = ?, type = ?, data = ?, updated_at = toTimestamp(now()) " + "WHERE id = ?";

  // Temp bootstrap
//  private static final String ip       = "192.168.49.20";
  private static final String hostIp   = "10.1.1.12";
  private static final String userId   = "cassandra";
  private static final String pwd      = "cassandra";
  private static final String dc       = "datacenter1";
//  private static final String certPath = "/media/tim/ExtraDrive1/Projects/009-SecureKeyAndCertRotation/proto-cass/src/main/resources/tls.crt";

  private CqlSession        session;

  private PreparedStatement insertStatement;
  private PreparedStatement selectByIdStatement;
  private PreparedStatement selectAllStatement;
  private PreparedStatement deleteStatement;
  private PreparedStatement updateStatement;

  public ScyllaDBVert()
  {
  }
  
  @Override
  public void start( Promise<Void> startPromise )
  {
    try
    {
      initializeCassandra().future().onComplete( result -> {
        if( result.succeeded() )
        {
          registerEventBusHandlers();
          startPromise.complete();
          logger.info( "Cassandra verticle started successfully" );
        } else
        {
          logger.error( "Failed to initialize Cassandra session", result.cause() );
          startPromise.fail( result.cause() );
        }
      } );
    } catch( Exception e )
    {
      logger.error( "Error starting Cassandra verticle", e );
      startPromise.fail( e );
    }
  }

  private Promise<Void> initializeCassandra()
  {
    Promise<Void> promise = Promise.promise();

    // This should be done asynchronously since it's a blocking operation
    vertx.executeBlocking( () -> {
      try
      {
        // Read configuration, default to localhost if not specified
        String contactPoint = config().getString( "cassandra.host", hostIp );
        int port = config().getInteger( "cassandra.port", 9042 );

        // Create session to Cassandra
        session = CqlSession.builder().addContactPoint( new InetSocketAddress( contactPoint, port ) )
                                      .withLocalDatacenter( dc )
                                      .withAuthCredentials( userId, pwd )
//                                      .withSslContext( SSLContextBuilder.build( certPath ))
                                      .build();
        
        // Create keyspace and table if they don't exist
        session.execute( CreateKeySpace );
        session.execute( UseKeySpace );
        session.execute( CreateTable );

        // Prepare statements
        insertStatement     = session.prepare( InsertStatement );
        selectByIdStatement = session.prepare( SelectByIdStatement );
        selectAllStatement  = session.prepare( SelectAllStatement );
        deleteStatement     = session.prepare( DeleteByIdStatement );
        updateStatement     = session.prepare( UpdateStatement );

        return Future.succeededFuture( "Operation completed successfully" );
      } 
      catch( Exception e )
      {
        logger.error( "Failed to initialize Cassandra", e );
        return Future.failedFuture( e );
      }
    } ).onComplete( ar -> {
      if( ar.succeeded() )
      {
        promise.complete();
      } else
      {
        promise.fail( ar.cause() );
      }
    } );

    return promise;
  }

  private void registerEventBusHandlers()
  {
    vertx.eventBus().consumer( "cassandra.save",   this::handleSave   );
    vertx.eventBus().consumer( "cassandra.get",    this::handleGet    );
    vertx.eventBus().consumer( "cassandra.getAll", this::handleGetAll );
    vertx.eventBus().consumer( "cassandra.delete", this::handleDelete );
    vertx.eventBus().consumer( "cassandra.update", this::handleUpdate );
  }

  private void handleSave( Message<JsonObject> message )
  {
//    Promise<Void> promise  = Promise.promise();
    JsonObject    metadata = message.body();

    // This should be done asynchronously since it's a blocking operation
    vertx.executeBlocking( () -> {
      try
      {
        UUID id = UUID.randomUUID();
        if( metadata.containsKey( "id" ) )
        {
          try
          {
            id = UUID.fromString( metadata.getString( "id" ) );
          } catch( IllegalArgumentException e )
          {
            // Use the generated UUID if the provided ID is invalid
          }
        }

        session.execute( insertStatement.bind( id, metadata.getString( "name" ), metadata.getString( "type" ), metadata.getString( "data" ) ) );

        metadata.put( "id", id.toString() );

        return Future.succeededFuture( "Operation completed successfully" );
      } catch( Exception e )
      {
        logger.error( "Failed to initialize Cassandra", e );
        throw e; // rethrow the exception
      }
    } ).onComplete( ar -> {
      if( ar.succeeded() )
      {
        message.reply(metadata);
//        promise.complete();
      } 
      else
      {
        message.reply("Error: " + ar.cause().getMessage()); // Send an error message as a reply
 //       promise.fail( ar.cause() );
      }
    } );

//    return promise;
  }

  private void handleGet( Message<String> message )
  {
    String     id      = message.body();

    vertx.executeBlocking( () -> {
      try
      {
        ResultSet  rs     = session.execute( selectByIdStatement.bind( UUID.fromString( id ) ) );
        Row        row    = rs.one();
        JsonObject result = null;

        if( row != null )
        {
          result = new JsonObject().put( "id", row.getUuid( "id" ).toString() )
                                   .put( "name", row.getString( "name" ) )
                                   .put( "type", row.getString( "type" ) )
                                   .put( "data", row.getString( "data" ) )
                                   .put( "created_at", row.getInstant( "created_at" ).toString() )
                                   .put( "updated_at", row.getInstant( "updated_at" ).toString() );

          return result;
        } 
        else
        { String msg = "Id not found for id = " + id;
          logger.info( msg );
          throw new NotFoundException( msg );
        }
      } 
      catch( Exception e )
      {
        logger.error( "Error getting metadata from Cassandra", e );
        throw e; // rethrow the exception
      }

    } ).onComplete( ar -> {
      if( ar.succeeded() )
      {
        message.reply( ar.result() );
      } else
      {
        message.fail( 500, ar.cause().getMessage() );
      }
    } );
  }

  private void handleGetAll( Message<Void> message )
  {
    vertx.executeBlocking( () -> {
      try
      {
        ResultSet rs = session.execute( selectAllStatement.bind() );
        List<JsonObject> results = rs.all().stream().map( row -> new JsonObject().put( "id", row.getUuid( "id" ).toString() ).put( "name", row.getString( "name" ) ).put( "type", row.getString( "type" ) ).put( "data", row.getString( "data" ) )
            .put( "created_at", row.getInstant( "created_at" ).toString() ).put( "updated_at", row.getInstant( "updated_at" ).toString() ) ).collect( Collectors.toList() );

        return new JsonArray( results );
      } catch( Exception e )
      {
        logger.error( "Error getting all metadata from Cassandra", e );
        throw e;
      }
    } ).onComplete( ar -> {
      if( ar.succeeded() )
      {
        message.reply( ar.result() );
      } else
      {
        message.fail( 500, ar.cause().getMessage() );
      }
    } );
  }

  private void handleDelete( Message<String> message )
  {
    String id = message.body();

    vertx.executeBlocking( () -> {
      try
      {
        ResultSet rs = session.execute( deleteStatement.bind( UUID.fromString( id ) ) );
        return rs.wasApplied(); // or a specific value if needed
      } catch( Exception e )
      {
        logger.error( "Error deleting metadata from Cassandra", e );
        throw e;
      }
    } ).onComplete( ar -> {
      if( ar.succeeded() )
      {
        message.reply( ar.result() );
      } else
      {
        message.fail( 500, ar.cause().getMessage() );
      }
    } );
  }

  private void handleUpdate( Message<JsonObject> message )
  {
    JsonObject metadata = message.body();

    vertx.executeBlocking( () -> 
    {
      try
      {
        UUID id = UUID.fromString( metadata.getString( "id" ) );

        ResultSet rs = session.execute( updateStatement.bind( metadata.getString( "name" ), metadata.getString( "type" ), metadata.getString( "data" ), id ) );

        return rs.wasApplied();
      } catch( Exception e )
      {
        logger.error( "Error updating metadata in Cassandra", e );
        throw e;
      }
    } ).onComplete( ar -> {
      if( ar.succeeded() )
      {
        message.reply( ar.result() );
      } else
      {
        message.fail( 500, ar.cause().getMessage() );
      }
    } );
  }

  @Override
  public void stop( Promise<Void> stopPromise )
  {
    if( session != null && !session.isClosed() )
    {
      try
      {
        session.close();
        logger.info( "Cassandra session closed" );
        stopPromise.complete();
      } catch( Exception e )
      {
        logger.error( "Error closing Cassandra session", e );
        stopPromise.fail( e );
      }
    } else
    {
      stopPromise.complete();
    }
  }
}
