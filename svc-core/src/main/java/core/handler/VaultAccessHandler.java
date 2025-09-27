package core.handler;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.json.JsonObject;

import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.ext.web.codec.BodyCodec;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * VaultAccessHandler - Simplified to only use working endpoints
 */
public class VaultAccessHandler implements AutoCloseable
{
  private static final Logger LOGGER = LoggerFactory.getLogger( VaultAccessHandler.class );

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
      else { // GET and other methods
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
      else {
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
   
  public void close()
  {
    if( vaultWorker != null )
      vaultWorker.close();
    if( webClient != null )
      webClient.close();
  }
}