package verticle;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.eventbus.EventBus;

import io.nats.client.*;
import io.nats.client.impl.Headers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.model.ServiceCoreIF;
import core.nats.NatsTLSClient;

import java.time.Duration;

/**
 * Metadata Client Consumer Verticle - Async Pull Consumer Implementation
 * 
 * Binds to admin-created pull consumer "metadata-client-requests" on stream METADATA_CLIENT.
 * Fetches messages in batches and processes metadata requests (save, get, update, delete).
 * 
 * @author t-snyder
 * @date 2025-11-04
 */
public class MetadataClientConsumerVert extends AbstractVerticle
{
  private static final Logger LOGGER = LoggerFactory.getLogger(MetadataClientConsumerVert.class);
  
  private static final String STREAM_NAME = "METADATA_CLIENT";
  private static final String DURABLE_NAME = "metadata-client-requests";
  private static final int BATCH_SIZE = 10;
  private static final long FETCH_TIMEOUT_MS = 500;
  private static final long PULL_INTERVAL_MS = 100;

  private NatsTLSClient natsTlsClient;
  private WorkerExecutor workerExecutor;
  private JetStreamSubscription subscription;

  public MetadataClientConsumerVert(NatsTLSClient natsTlsClient)
  {
    this.natsTlsClient = natsTlsClient;
  }

  @Override
  public void start(Promise<Void> startPromise)
  {
    workerExecutor = vertx.createSharedWorkerExecutor("msg-handler");
    
    startRequestConsumer()
      .onSuccess(result -> 
      {
        LOGGER.info("MetadataClientConsumerVert started successfully with async pull consumer");
        startPromise.complete();
      })
      .onFailure(throwable -> 
      {
        String msg = "Failed to initialize MetadataClientConsumerVert: " + throwable.getMessage();
        LOGGER.error(msg, throwable);
        cleanup();
        startPromise.fail(msg);
      });
  }

  /**
   * Bind to admin-created pull consumer and start fetching - ASYNC VERSION
   */
  private Future<Void> startRequestConsumer() 
  {
    LOGGER.info("Binding to async pull consumer: stream={} durable={}", STREAM_NAME, DURABLE_NAME);

    Promise<Void> promise = Promise.promise();

    natsTlsClient.getConsumerPoolManager().bindPullConsumerAsync(
      STREAM_NAME,
      DURABLE_NAME,
      this::handleRequestMessageAsync,  // ASYNC handler - returns Future<Void>
      BATCH_SIZE,
      FETCH_TIMEOUT_MS,
      PULL_INTERVAL_MS
    )
    .onSuccess(sub -> 
    {
      this.subscription = sub;
      LOGGER.info("Bound to async pull consumer: stream={} durable={} batchSize={}", 
                 STREAM_NAME, DURABLE_NAME, BATCH_SIZE);
      promise.complete();
    })
    .onFailure(err -> 
    {
      LOGGER.error("Failed to bind to async pull consumer: {}", err.getMessage(), err);
      cleanup();
      promise.fail(err);
    });

    return promise.future();
  }

  /**
   * Handle individual metadata request message - ASYNC VERSION
   * Returns Future that completes when processing is done (success = ack, failure = nak)
   */
  private Future<Void> handleRequestMessageAsync(Message msg)
  {
    Promise<Void> promise = Promise.promise();
    
    try
    {
      Headers headers = msg.getHeaders();
      String eventType = null;
      
      if (headers != null)
      {
        eventType = headers.getFirst(ServiceCoreIF.MsgHeaderEventType);
      }
      
      if (eventType == null)
      {
        LOGGER.warn("Message missing event type header - skipping");
        promise.fail(new RuntimeException("Missing event type header"));
        return promise.future();
      }

      // Make eventType final for use in lambda
      final String finalEventType = eventType;

      LOGGER.debug("Processing message with eventType: {}", finalEventType);
      
      EventBus eventBus = vertx.eventBus();

      Future<String> processingFuture;
      
      switch (finalEventType)
      {
        case "cert-notify":
          processingFuture = processCertNotify(msg);
          break;
        case "save":
          processingFuture = processSave(msg);
          break;
        case "get":
          processingFuture = processGet(msg);
          break;
        case "getAll":
          processingFuture = processGetAll(msg);
          break;
        case "update":
          processingFuture = processUpdate(msg);
          break;
        case "delete":
          processingFuture = processDelete(msg);
          break;
        default:
          LOGGER.warn("Unknown eventType: {}", finalEventType);
          promise.fail(new RuntimeException("Unknown event type: " + finalEventType));
          return promise.future();
      }

      // Send to event bus and handle response
      processingFuture
        .compose(jsonStr -> {
          String busAddress = getBusAddressForEventType(finalEventType);
          return eventBus.<byte[]>request(busAddress, jsonStr.getBytes())
            .mapEmpty();
        })
        .onComplete(ar -> {
          if (ar.succeeded())
          {
            LOGGER.debug("Request processed successfully for eventType: {}", finalEventType);
            promise.complete();
          }
          else
          {
            LOGGER.error("Request processing failed for eventType {}: {}", 
                        finalEventType, ar.cause().getMessage(), ar.cause());
            promise.fail(ar.cause());
          }
        });
    }
    catch (Exception e)
    {
      LOGGER.error("Exception in handleRequestMessageAsync: {}", e.getMessage(), e);
      promise.fail(e);
    }
    
    return promise.future();
  }

  /**
   * Get event bus address for event type
   */
  private String getBusAddressForEventType(String eventType)
  {
    switch (eventType)
    {
      case "cert-notify": return "nats.cert.notify";
      case "save": return "cassandra.save";
      case "get": return "cassandra.get";
      case "getAll": return "cassandra.get";
      case "update": return "cassandra.update";
      case "delete": return "cassandra.delete";
      default: return "cassandra.unknown";
    }
  }

  private Future<String> processCertNotify(Message msg)
  {
    // Implementation depends on your message structure
    // Return Future<String> with JSON
    return Future.succeededFuture("{}");
  }
  
  private Future<String> processSave(Message msg)
  {
    // Implementation depends on your message structure
    // Extract data from msg.getData() and build JSON
    return Future.succeededFuture("{}");
  }
  
  private Future<String> processGet(Message msg)
  {
    // Implementation depends on your message structure
    return Future.succeededFuture("{}");
  }

  private Future<String> processGetAll(Message msg)
  {
    // Implementation depends on your message structure
    return Future.succeededFuture("{}");
  }

  private Future<String> processUpdate(Message msg)
  {
    // Implementation depends on your message structure
    return Future.succeededFuture("{}");
  }

  private Future<String> processDelete(Message msg)
  {
    // Implementation depends on your message structure
    return Future.succeededFuture("{}");
  }
  
  @Override
  public void stop(Promise<Void> stopPromise) 
  {
    try 
    {
      cleanup();
      LOGGER.info("MetadataClientConsumerVert stopped");
      stopPromise.complete();
    } 
    catch (Exception e)
    {
      LOGGER.error("Error stopping MetadataClientConsumerVert", e);
      stopPromise.fail(e);
    }
  }
 
  private void cleanup() 
  {
    // Close worker executor
    if (workerExecutor != null) 
    {
      try 
      {
        workerExecutor.close();
        LOGGER.info("Closed worker executor");
      }
      catch (Exception e) 
      {
        LOGGER.warn("Error closing worker executor: {}", e.getMessage(), e);
      }
    }
    
    // Close subscription (pull timer is managed by pool manager)
    if (subscription != null) 
    {
      try 
      {
        if (subscription.isActive())
        {
          subscription.drain(Duration.ofSeconds(2));
          subscription.unsubscribe();
        }
        LOGGER.info("Closed subscription");
      }
      catch (Exception e) 
      {
        LOGGER.warn("Error closing subscription: {}", e.getMessage(), e);
      }
    }
    
    LOGGER.info("MetadataClientConsumerVert cleanup completed");
  }  
}