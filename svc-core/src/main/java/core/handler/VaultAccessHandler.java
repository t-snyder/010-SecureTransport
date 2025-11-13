package core.handler;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.ext.web.codec.BodyCodec;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.model.CaBundle;
import core.model.ServiceBundle;

/**
 * VaultAccessHandler - Simplified to only use working endpoints
 */
public class VaultAccessHandler implements AutoCloseable
{
  private static final Logger LOGGER = LoggerFactory.getLogger( VaultAccessHandler.class );

  // Vault paths
  private static final String SERVICE_BUNDLE_VAULT_MOUNT       = "secret";
  private static final String SERVICE_BUNDLE_VAULT_PATH_PREFIX = "service-bundles";
  private static final String CA_BUNDLE_VAULT_PATH_PREFIX      = "ca-bundles";

  // Default values
  private static final int DEFAULT_CONNECT_TIMEOUT = 10000;
  private static final int DEFAULT_IDLE_TIMEOUT    = 10000;

  private final Vertx     vertx;
  private final WebClient webClient;
  private final String    vaultAgentAddr;
  private final String    vaultAgentHost;
  private final int       vaultAgentPort;
  private final String    vaultTokenPath;

  private final WorkerExecutor vaultWorker;

  public VaultAccessHandler( Vertx vertx, String serviceId, String vaultAgentAddr, String vaultAgentHost, int vaultAgentPort, String tokenPath )
  {
    this.vertx          = vertx;
    this.vaultAgentAddr = vaultAgentAddr;
    this.vaultAgentHost = vaultAgentHost;
    this.vaultAgentPort = vaultAgentPort;
    this.vaultTokenPath = tokenPath;

    WebClientOptions options = new WebClientOptions()
        .setConnectTimeout(DEFAULT_CONNECT_TIMEOUT)
        .setIdleTimeout(DEFAULT_IDLE_TIMEOUT)
        .setDefaultHost( vaultAgentHost )
        .setDefaultPort( vaultAgentPort );

    this.webClient = WebClient.create( vertx, options );

    // 10 Threads, 5 minute max execution
    this.vaultWorker = this.vertx.createSharedWorkerExecutor( "vault-worker", 10, 300000 );
  }

  /** Reads Vault token from the agent-rendered file */
  public Future<String> getVaultToken()
  {
    Promise<String> promise = Promise.promise();
    vaultWorker.executeBlocking( () ->
    {
      try
      {
        String token = Files.readString( Paths.get( vaultTokenPath ) ).trim();
        if( token == null || token.isEmpty() )
        {
          throw new Exception( "Vault token not found at: " + vaultTokenPath );
        }
        return token;
      }
      catch( Exception e )
      {
        LOGGER.error( "Vault token read failed", e );
        throw new RuntimeException( e );
      }
    } ).onComplete( ar ->
        {
          if( ar.succeeded() )
            promise.complete( (String)ar.result() );
          else
            promise.fail( ar.cause() );
        } );

    return promise.future();
  }

  /**
   * Request new secret ID for AppRole authentication
   */
  public Future<String> requestNewSecretId( String vaultRoleName, String token )
  {
    Promise<String> promise = Promise.promise();

    String apiUrl = "/v1/auth/approle/role/" + vaultRoleName + "/secret-id";

    webClient.post( vaultAgentPort, vaultAgentHost, apiUrl )
             .putHeader( "X-Vault-Token", token )
             .putHeader( "Content-Type", "application/json" )
             .as( BodyCodec.string() )
             .sendJsonObject( new JsonObject() )
             .onSuccess( response ->
    {
      if( response.statusCode() != 200 )
      {
        LOGGER.error( "Failed to get new secret_id from Vault (code={}): {}", response.statusCode(), response.body() );
        promise.fail( "Vault Agent returned non-200 status" );
      }
      else
      {
        try
        {
          JsonObject body = new JsonObject( response.body() );
          String secretId = body.getJsonObject( "data" ).getString( "secret_id" );

          LOGGER.info( "Obtained new secret_id from Vault for role {}.", vaultRoleName );
          promise.complete( secretId );
        }
        catch( Exception e )
        {
          LOGGER.error( "Failed to parse Vault response: {}", e.getMessage() );
          promise.fail( e );
        }
      }
    } ).onFailure( err ->
       {
         LOGGER.error( "Failed to call Vault Agent for secret-id: {}", err.getMessage() );
         promise.fail( err );
       } );

    return promise.future();
  }

  /** Generic Vault API request via the Agent  with json object payload */
  public Future<JsonObject> vaultRequest( String method, String path, String payloadJson )
  {
    Promise<JsonObject> promise = Promise.promise();

    getVaultToken().onSuccess( token ->
    {
      String url = vaultAgentAddr + path;
      LOGGER.debug( "vaultRequest for path = " + url );

      if( "POST".equalsIgnoreCase( method ))
      {
        JsonObject payload = payloadJson != null ? new JsonObject( payloadJson ) : new JsonObject();

        webClient.postAbs( url )
                 .putHeader( "X-Vault-Token", token )
                 .putHeader( "Content-Type", "application/json" )
                 .as( BodyCodec.string() )
                 .sendJsonObject( payload )
                 .onSuccess( response -> handleVaultResponse( response, promise ))
                 .onFailure(  err ->
                 {
                   LOGGER.error( "Vault POST HTTP request failed for url = " + url + "; error = " + err.getMessage());
                   promise.fail( err );
                 });
      }
      else if("LIST".equalsIgnoreCase(method)) {
        webClient.getAbs(url)
                 .addQueryParam("list", "true")
                 .putHeader("X-Vault-Token", token)
                 .as(BodyCodec.string())
                 .send()
                 .onSuccess(response -> handleVaultResponse(response, promise))
                 .onFailure(err -> {
                   LOGGER.error("Vault LIST HTTP request failed for url = " + url + "; error = " + err.getMessage());
                   promise.fail(err);
                 });
      }
      else if("DELETE".equalsIgnoreCase(method)) {
        webClient.deleteAbs(url)
                 .putHeader("X-Vault-Token", token)
                 .as(BodyCodec.string())
                 .send()
                 .onSuccess(response -> handleVaultResponse(response, promise))
                 .onFailure(err -> {
                   LOGGER.error("Vault DELETE HTTP request failed for url = " + url + "; error = " + err.getMessage());
                   promise.fail(err);
                 });
      }  
      else { // GET and other methods - treated as GET here
        webClient.getAbs(url)
                 .putHeader("X-Vault-Token", token)
                 .as(BodyCodec.string())
                 .send()
                 .onSuccess(response -> handleVaultResponse(response, promise))
                 .onFailure(err -> {
                   LOGGER.error("Vault GET HTTP request failed for url = " + url + "; error = " + err.getMessage());
                   promise.fail(err);
                 });
      }
    }).onFailure(promise::fail);

    return promise.future();
  }

  /**
   * Raw Vault API request that returns the response body as a String.
   * Use this for endpoints that return PEM data directly.
   */
  public Future<String> vaultRequestRaw( String method, String path, String payloadJson )
  {
    Promise<String> promise = Promise.promise();

    getVaultToken().onSuccess( token ->
    {
      String url = vaultAgentAddr + path;
      LOGGER.debug( "vaultRequestRaw for path = " + url );

      if( "POST".equalsIgnoreCase( method ))
      {
        JsonObject payload = payloadJson != null ? new JsonObject( payloadJson ) : new JsonObject();

        webClient.postAbs( url )
                 .putHeader( "X-Vault-Token", token )
                 .putHeader( "Content-Type", "application/json" )
                 .as( BodyCodec.string() )
                 .sendJsonObject( payload )
                 .onSuccess( response -> handleVaultRawResponse( response, promise ))
                 .onFailure(  err ->
                 {
                   LOGGER.error( "Vault POST HTTP request failed for url = " + url + "; error = " + err.getMessage());
                   promise.fail( err );
                 });
      }
      else if("LIST".equalsIgnoreCase(method)) {
        webClient.getAbs(url)
                 .addQueryParam("list", "true")
                 .putHeader("X-Vault-Token", token)
                 .as(BodyCodec.string())
                 .send()
                 .onSuccess(response -> handleVaultRawResponse(response, promise))
                 .onFailure(err -> {
                   LOGGER.error("Vault LIST HTTP request failed for url = " + url + "; error = " + err.getMessage());
                   promise.fail(err);
                 });
      }
      else if("DELETE".equalsIgnoreCase(method)) {
        webClient.deleteAbs(url)
                 .putHeader("X-Vault-Token", token)
                 .as(BodyCodec.string())
                 .send()
                 .onSuccess(response -> handleVaultRawResponse(response, promise))
                 .onFailure(err -> {
                   LOGGER.error("Vault DELETE HTTP request failed for url = " + url + "; error = " + err.getMessage());
                   promise.fail(err);
                 });
      }
      else 
      {
        webClient.getAbs(url)
                 .putHeader("X-Vault-Token", token)
                 .as(BodyCodec.string())
                 .send()
                 .onSuccess(response -> handleVaultRawResponse(response, promise))
                 .onFailure(err -> {
                   LOGGER.error("Vault GET HTTP request failed for url = " + url + "; error = " + err.getMessage());
                   promise.fail(err);
                 });
      }
    }).onFailure(promise::fail);

    return promise.future();
  }

  /**
   * Handle Vault JSON response consistently
   */
  private void handleVaultResponse(io.vertx.ext.web.client.HttpResponse<String> response, Promise<JsonObject> promise)
  {
    if( response.statusCode() < 200 || response.statusCode() >= 300 )
    {
      String errorMsg = "Vault request failed (status " + response.statusCode() + "): " + response.body();
      LOGGER.error(errorMsg);
      promise.fail(errorMsg);
    }
    else
    {
      try
      {
        String responseBody = response.body();
        if( responseBody == null || responseBody.trim().isEmpty() )
        {
          promise.complete( new JsonObject() );
        }
        else
        {
          promise.complete( new JsonObject( responseBody ));
        }
      }
      catch( Exception e )
      {
        LOGGER.error("Failed to parse Vault response: {}", e.getMessage());
        promise.fail(e);
      }
    }
  }

  /**
   * Handle Vault raw response (for PEM data)
   */
  private void handleVaultRawResponse(io.vertx.ext.web.client.HttpResponse<String> response, Promise<String> promise)
  {
    if( response.statusCode() < 200 || response.statusCode() >= 300 )
    {
      String errorMsg = "Vault request failed (status " + response.statusCode() + "): " + response.body();
      LOGGER.error(errorMsg);
      promise.fail(errorMsg);
    }
    else
    {
      String responseBody = response.body();
      promise.complete( responseBody != null ? responseBody : "" );
    }
  }

  /**
   * Retrieve a ServiceBundle for a given serviceId and epoch.
   * Vault path: secret/data/service-bundles/{serviceId}/{epoch}
   */
  public Future<ServiceBundle> getServiceBundle(String serviceId, long epoch)
  {
    String path = String.format("%s/%s/%d", SERVICE_BUNDLE_VAULT_PATH_PREFIX, serviceId, epoch);
    String apiUrl = "/v1/" + SERVICE_BUNDLE_VAULT_MOUNT + "/data/" + path;

    return vaultRequest("GET", apiUrl, null)
      .compose(response -> {
        try {
          JsonObject dataOuter = response.getJsonObject("data");
          if (dataOuter == null)
            return Future.failedFuture("No data field in response for " + serviceId + " at epoch " + epoch);
          JsonObject dataInner = dataOuter.getJsonObject("data");
          if (dataInner == null)
            return Future.failedFuture("No inner data field in response for " + serviceId + " at epoch " + epoch);
          String base64Bundle = dataInner.getString("bundle", null);
          if (base64Bundle == null || base64Bundle.trim().isEmpty())
            return Future.failedFuture("No bundle found for " + serviceId + " at epoch " + epoch);

          return vaultWorker.executeBlocking(() -> {
            byte[] avroBytes = Base64.getDecoder().decode(base64Bundle);
            return ServiceBundle.deSerialize(avroBytes);
          });
        } catch (Exception e) {
          return Future.failedFuture(e);
        }
      });
  }

  /**
   * List all epoch keys for a serviceId.
   * Vault path: secret/metadata/service-bundles/{serviceId}
   */
  public Future<List<String>> listServiceBundleEpochs(String serviceId)
  {
    String path = String.format("%s/%s", SERVICE_BUNDLE_VAULT_PATH_PREFIX, serviceId);
    String apiUrl = "/v1/" + SERVICE_BUNDLE_VAULT_MOUNT + "/metadata/" + path;

    return vaultRequest("LIST", apiUrl, null)
      .map(response -> {
        JsonObject data = response.getJsonObject("data");
        if (data == null)
          return new ArrayList<String>();
        JsonArray keysArray = data.getJsonArray("keys");
        if (keysArray == null)
          return new ArrayList<String>();
        List<String> epochs = new ArrayList<>();
        for (int i = 0; i < keysArray.size(); i++) {
          String key = keysArray.getString(i);
          if (key.endsWith("/"))
            key = key.substring(0, key.length() - 1);
          epochs.add(key);
        }
        return epochs;
      });
  }

  /**
   * Retrieve all ServiceBundles for a given serviceId (all epochs).
   */
  public Future<List<ServiceBundle>> getAllServiceBundles(String serviceId)
  {
    return listServiceBundleEpochs(serviceId)
      .compose(epochKeys -> {
        List<Future<ServiceBundle>> futures = new ArrayList<>();
        for (String epoch : epochKeys) {
          try {
            long epochLong = Long.parseLong(epoch);
            futures.add(getServiceBundle(serviceId, epochLong).recover(err -> Future.succeededFuture(null)));
          } catch (NumberFormatException nfe) {
            LOGGER.warn("Ignoring invalid epoch key: {}", epoch);
          }
        }
        return Future.all(futures).map(cf -> {
          List<ServiceBundle> bundles = new ArrayList<>();
          for (Object b : cf.list()) {
            if (b instanceof ServiceBundle && b != null) {
              bundles.add((ServiceBundle) b);
            }
          }
          return bundles;
        });
      });
  }

  /**
   * Retrieve a CaBundle for a given serverId and CA epoch.
   * Vault path: secret/data/ca-bundles/{serverId}/{caEpoch}
   */
  public Future<CaBundle> getCaBundle(String serverId, long caEpoch)
  {
    String path = String.format("%s/%s/%d", CA_BUNDLE_VAULT_PATH_PREFIX, serverId, caEpoch);
    String apiUrl = "/v1/" + SERVICE_BUNDLE_VAULT_MOUNT + "/data/" + path;

    return vaultRequest("GET", apiUrl, null)
      .compose(response -> {
        try {
          JsonObject dataOuter = response.getJsonObject("data");
          if (dataOuter == null) {
            return Future.failedFuture("No data field in response for " + serverId + " at CA epoch " + caEpoch);
          }
          
          JsonObject dataInner = dataOuter.getJsonObject("data");
          if (dataInner == null) {
            return Future.failedFuture("No inner data field in response for " + serverId + " at CA epoch " + caEpoch);
          }
          
          String base64Bundle = dataInner.getString("bundle", null);
          if (base64Bundle == null || base64Bundle.trim().isEmpty()) {
            return Future.failedFuture("No bundle found for " + serverId + " at CA epoch " + caEpoch);
          }

          return vaultWorker.executeBlocking(() -> {
            byte[] avroBytes = Base64.getDecoder().decode(base64Bundle);
            return CaBundle.deSerialize(avroBytes);
          });
        } catch (Exception e) {
          LOGGER.error("Failed to deserialize CaBundle for {} at epoch {}: {}", 
                      serverId, caEpoch, e.getMessage(), e);
          return Future.failedFuture(e);
        }
      });
  }

  /**
   * List all CA epoch keys for a serverId.
   * Vault path: secret/metadata/ca-bundles/{serverId}
   */
  public Future<List<Long>> listCaBundleEpochs(String serverId)
  {
    String path = String.format("%s/%s", CA_BUNDLE_VAULT_PATH_PREFIX, serverId);
    String apiUrl = "/v1/" + SERVICE_BUNDLE_VAULT_MOUNT + "/metadata/" + path;

    return vaultRequest("LIST", apiUrl, null)
      .map(response -> {
        JsonObject data = response.getJsonObject("data");
        if (data == null) {
          return new ArrayList<Long>();
        }
        
        JsonArray keysArray = data.getJsonArray("keys");
        if (keysArray == null) {
          return new ArrayList<Long>();
        }
        
        List<Long> epochs = new ArrayList<>();
        for (int i = 0; i < keysArray.size(); i++) {
          String key = keysArray.getString(i);
          if (key.endsWith("/")) {
            key = key.substring(0, key.length() - 1);
          }
          try {
            epochs.add(Long.parseLong(key));
          } catch (NumberFormatException nfe) {
            LOGGER.warn("Ignoring invalid CA epoch key: {}", key);
          }
        }
        return epochs;
      });
  }

  /**
   * Retrieve all CaBundles for a given serverId (all CA epochs).
   */
  public Future<List<CaBundle>> getAllCaBundles(String serverId)
  {
    return listCaBundleEpochs(serverId)
      .compose(epochKeys -> {
        if (epochKeys == null || epochKeys.isEmpty()) {
          LOGGER.info("No CA bundles found for server {}", serverId);
          return Future.succeededFuture(new ArrayList<CaBundle>());
        }
        
        List<Future<CaBundle>> futures = new ArrayList<>();
        for (Long epoch : epochKeys) {
          futures.add(getCaBundle(serverId, epoch).recover(err -> {
            LOGGER.warn("Failed to retrieve CA bundle for {} at epoch {}: {}", 
                       serverId, epoch, err.getMessage());
            return Future.succeededFuture(null);
          }));
        }
        
        return Future.all(futures).map(cf -> 
        {
          List<CaBundle> bundles = new ArrayList<>();
          for (Object b : cf.list()) {
            if (b instanceof CaBundle && b != null) {
              bundles.add((CaBundle) b);
            }
          }
          LOGGER.info("Retrieved {} CA bundles for server {}", bundles.size(), serverId);
          return bundles;
        });
      });
  }

  /**
   * Get the most recent CaBundle for a given serverId.
   * This is useful for services that just need the current CA bundle.
   */
  public Future<CaBundle> getCurrentCaBundle(String serverId)
  {
    return listCaBundleEpochs(serverId)
      .compose( epochs -> 
      {
        if( epochs == null || epochs.isEmpty() ) 
        {
          return Future.failedFuture("No CA bundles found for server " + serverId);
        }
        
        // Get the highest epoch number (most recent)
        Long maxEpoch = Collections.max(epochs);
        LOGGER.info("Retrieving current CA bundle for server {} at epoch {}", serverId, maxEpoch);
        
        return getCaBundle(serverId, maxEpoch);
      });
  } 
  
  public void close()
  {
    if( vaultWorker != null )
      vaultWorker.close();
    if( webClient != null )
      webClient.close();
  }
}