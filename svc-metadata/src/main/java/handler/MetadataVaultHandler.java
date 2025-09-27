package handler;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.Promise;
import io.vertx.core.CompositeFuture;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.handler.VaultAccessHandler;

/**
 * Specialized Vault handler for Metadata service operations. Pre-collects existing
 * certificates before rotation to avoid timing issues.
 *
 * Enhanced getCAChainEnhanced implementation: try multiple endpoints and fallbacks,
 * parse both raw PEM responses and JSON responses that contain certificate fields,
 * and as a last resort attempt to assemble chain from issuer/<id>/pem entries.
 */
public class MetadataVaultHandler
{
  private static final Logger LOGGER = LoggerFactory.getLogger( MetadataVaultHandler.class );

  // Vault paths
  private static final String METADATA_PKI_PATH = "metadata_pki";

  private final Vertx vertx;
  private final VaultAccessHandler vaultHandler;
  private final WorkerExecutor workerExecutor;

  public MetadataVaultHandler( Vertx vertx, VaultAccessHandler vaultHandler )
  {
    this.vertx = vertx;
    this.vaultHandler = vaultHandler;
    this.workerExecutor = vertx.createSharedWorkerExecutor("metadata-vault-worker", 5, 300000);
  }

  public VaultAccessHandler getVaultHandler() { return vaultHandler; }
  
  /*****************************************************************************/
  /* Vault Policy Management Methods */

  public Future<Void> createServiceTopicPolicy( String serviceId, List<String> topicPaths )
  {
    StringBuilder policy = new StringBuilder();
    policy.append( "# Auto-generated policy for service: " ).append( serviceId ).append( "\n" );

    for( String topicPath : topicPaths )
    {
      policy.append( String.format( "path \"secret/data/topic-keys/%s\" {\n", topicPath ) )
            .append( "  capabilities = [\"read\"]\n" )
            .append( "}\n\n" );
    }

    String policyName = "service-" + serviceId + "-topic-access";
    String apiPath = "/v1/sys/policies/acl/" + policyName;

    JsonObject policyData = new JsonObject().put( "policy", policy.toString() );

    return vaultHandler.vaultRequest( "POST", apiPath, policyData.encode() )
                       .compose( response -> 
                        {
                          LOGGER.info( "Stored policy for: {}", serviceId );
                          return Future.<Void> succeededFuture( null );
                        })
                       .recover( err -> 
                        {
                          LOGGER.error( "Failed to store policy for {}: {}", serviceId, err.getMessage() );
                          return Future.failedFuture( err );
                        });
  }

  public Future<Void> updateServicePermissions( String serviceId, java.util.Set<String> topicPaths )
  {
    List<String> paths = new ArrayList<>( topicPaths );
    return createServiceTopicPolicy( serviceId, paths );
  }

  /*****************************************************************************/
  /* Enhanced PKI CA Rotation Methods - Pre-collection approach */

  /**
   * Pre-collect existing CA certificates before rotation
   * This avoids timing issues with Vault after certificate updates
   */
  public Future<ExistingCertificates> preCollectExistingCertificates(String pkiMount, String rootPkiPath) {
    LOGGER.info("Pre-collecting existing certificates before rotation from {} and {}", pkiMount, rootPkiPath);
    
    return getExistingIntermediateCertificates(pkiMount)
        .compose(existingIntermediates -> {
            return getRootCACertificate(rootPkiPath)
                .map(rootCert -> {
                    ExistingCertificates existing = new ExistingCertificates(existingIntermediates, rootCert);
                    LOGGER.info("Pre-collected {} existing intermediate(s) and root CA ({} chars)", 
                               existingIntermediates.size(), rootCert != null ? rootCert.length() : 0);
                    return existing;
                });
        });
  }
  
  /**
   * Get existing intermediate certificates from PKI mount
   */
  private Future<List<String>> getExistingIntermediateCertificates( String pkiMount ) 
  {
    LOGGER.info("Collecting existing intermediate certificates from {}", pkiMount);
    
    return listPkiIssuerIds(pkiMount)
      .compose( issuerIds -> 
      {
            if (issuerIds.isEmpty()) {
                LOGGER.info("No existing issuers found in PKI mount {}", pkiMount);
                return Future.succeededFuture(new ArrayList<String>());
            }
            
            LOGGER.info("Found {} existing issuers, retrieving certificates", issuerIds.size());
            
            // Get certificates for all existing issuers
            List<Future<String>> certFutures = issuerIds.stream()
                .map(issuerId -> getIssuerCertificate(pkiMount, issuerId))
                .collect(Collectors.toList());
            
            // In Vert.x 5.0, Future.all() returns CompositeFuture, use list() method
            return Future.all(certFutures)
              .map( compositeFuture -> 
               {
                    List<String> certificates = new ArrayList<>();
                    
                    // Use list() method to get List<Object>, then cast each element
                    List<Object> results = compositeFuture.list();
                    for (Object result : results) {
                        String cert = (String) result;
                        if (cert != null && !cert.trim().isEmpty() && 
                            cert.contains("-----BEGIN CERTIFICATE-----")) {
                            certificates.add(cert.trim());
                        }
                    }
                    LOGGER.info("Retrieved {} valid existing intermediate certificates", certificates.size());
                    return certificates;
                });
        })
        .recover(err -> {
            LOGGER.warn("Failed to collect existing intermediates: {}, continuing with empty list", err.getMessage());
            return Future.succeededFuture(new ArrayList<String>());
        });
  }
  
  /**
   * Get certificate for a specific issuer
   */
  private Future<String> getIssuerCertificate(String pkiMount, String issuerId) {
    // Try multiple methods to get the issuer certificate
    return getIssuerCertificateViaPem(pkiMount, issuerId)
        .recover(err -> {
            LOGGER.debug("PEM endpoint failed for issuer {}, trying issuer info", issuerId);
            return getIssuerCertificateViaInfo(pkiMount, issuerId);
        });
  }

  private Future<String> getIssuerCertificateViaPem(String pkiMount, String issuerId) {
    String endpoint = "/v1/" + pkiMount + "/issuer/" + issuerId + "/pem";
    
    return vaultHandler.vaultRequestRaw("GET", endpoint, null)
        .map(cert -> {
            if (cert != null && cert.contains("-----BEGIN CERTIFICATE-----")) {
                LOGGER.debug("Retrieved certificate for issuer {} via PEM endpoint", issuerId);
                return cert;
            } else {
                throw new RuntimeException("Invalid PEM response for issuer " + issuerId);
            }
        });
  }

  private Future<String> getIssuerCertificateViaInfo(String pkiMount, String issuerId) {
    return getIssuerInfo(pkiMount, issuerId)
        .map(issuerData -> {
            String cert = issuerData.getString("certificate", "");
            if (cert != null && cert.contains("-----BEGIN CERTIFICATE-----")) {
                LOGGER.debug("Retrieved certificate for issuer {} via issuer info", issuerId);
                return cert;
            } else {
                throw new RuntimeException("No valid certificate in issuer info for " + issuerId);
            }
        });
  }

  /**
   * Get root CA certificate
   */
  private Future<String> getRootCACertificate(String rootPkiPath) {
    LOGGER.info("Retrieving root CA certificate from {}", rootPkiPath);
    
    String[] endpoints = {
        "/v1/" + rootPkiPath + "/ca/pem",
        "/v1/" + rootPkiPath + "/ca",
        "/v1/" + rootPkiPath + "/cert/ca"
    };
    
    return tryRootEndpoints(endpoints, 0);
  }

  private Future<String> tryRootEndpoints(String[] endpoints, int index) {
    if (index >= endpoints.length) {
        return Future.failedFuture("All root CA endpoints failed");
    }

    String endpoint = endpoints[index];
    LOGGER.debug("Trying root CA endpoint: {}", endpoint);

    return vaultHandler.vaultRequestRaw("GET", endpoint, null)
        .compose(response -> {
            if (response != null && !response.trim().isEmpty() && 
                response.contains("-----BEGIN CERTIFICATE-----")) {
                LOGGER.info("Successfully retrieved root CA from {}", endpoint);
                return Future.succeededFuture(response.trim());
            } else {
                LOGGER.debug("Endpoint {} returned invalid response, trying next", endpoint);
                return tryRootEndpoints(endpoints, index + 1);
            }
        })
        .recover(err -> {
            LOGGER.debug("Root endpoint {} failed: {}", endpoint, err.getMessage());
            return tryRootEndpoints(endpoints, index + 1);
        });
  }

  /**
   * Build complete CA bundle from pre-collected certificates + new intermediate
   */
  public Future<String> buildCompleteCABundleWithNew(ExistingCertificates existing, String newIntermediateCert) {
    return workerExecutor.executeBlocking(() -> {
        StringBuilder bundle = new StringBuilder();
        int certCount = 0;
        
        // 1. Add the new intermediate certificate first (most recent)
        if (newIntermediateCert != null && !newIntermediateCert.trim().isEmpty()) {
            bundle.append(newIntermediateCert.trim());
            certCount++;
            LOGGER.info("Added new intermediate certificate ({} chars)", newIntermediateCert.length());
        }
        
        // 2. Add existing intermediate certificates
        for (String existingCert : existing.getIntermediateCertificates()) {
            if (bundle.length() > 0) bundle.append("\n");
            bundle.append(existingCert);
            certCount++;
        }
        
        // 3. Add root certificate
        if (existing.getRootCertificate() != null && !existing.getRootCertificate().trim().isEmpty()) {
            if (bundle.length() > 0) bundle.append("\n");
            bundle.append(existing.getRootCertificate());
            certCount++;
        }
        
        String result = bundle.toString();
        LOGGER.info("Built complete CA bundle: 1 new + {} existing intermediates + 1 root = {} total certificates ({} chars)", 
                   existing.getIntermediateCertificates().size(), certCount, result.length());
        
        return result;
    });
  }

  public Future<CsrWithKeyId> generateIntermediateCsrInternal(String pkiMount, String commonName, String keyType, int keyBits) {
    String apiUrl = "/v1/" + pkiMount + "/intermediate/generate/internal";

    JsonObject payload = new JsonObject()
        .put("common_name", commonName)
        .put("key_type", keyType)
        .put("key_bits", keyBits);

    LOGGER.info("Generating intermediate CSR for {} using endpoint: {}", commonName, apiUrl);

    return vaultHandler.vaultRequest("POST", apiUrl, payload.encode())
        .map(response -> {
            JsonObject data = response.getJsonObject("data");
            if (data == null || !data.containsKey("csr")) {
                throw new IllegalStateException("Invalid response from Vault: missing CSR in response");
            }

            String csr = data.getString("csr");
            String keyId = data.getString("key_id");
            
            LOGGER.info("Successfully generated CSR with internal private key (key_id: {}) for {}", 
                       keyId != null ? keyId : "auto-generated", commonName);
            
            return new CsrWithKeyId(csr, keyId);
        });
  }  

  public Future<String> signCsrWithRoot( String rootPkiPath, String csr, String ttl )
  {
    String apiUrl = "/v1/" + rootPkiPath + "/root/sign-intermediate";

    JsonObject payload = new JsonObject()
        .put( "csr", csr )
        .put( "format", "pem_bundle" )
        .put( "ttl", ttl );

    LOGGER.info("Signing CSR with root CA using endpoint: {}", apiUrl);

    return vaultHandler.vaultRequest( "POST", apiUrl, payload.encode() ).map( response -> {
      JsonObject data = response.getJsonObject( "data" );
      if( data == null || !data.containsKey( "certificate" ) )
      {
        throw new IllegalStateException( "Invalid response from Vault: missing certificate in response" );
      }

      String signedCert = data.getString( "certificate" );
      LOGGER.info( "Successfully signed intermediate CSR with root CA, TTL: {}", ttl );
      return signedCert;
    } );
  }

  /**
   * Install the signed intermediate certificate into the intermediate mount.
   * Returns the issuerId if it can be discovered OR null if the endpoint is unavailable or issuer can't be determined.
   * Does not fail the rotation for 404/permission errors on set-signed; returns succeededFuture(null) in that case.
   */
  public Future<String> setIntermediateSignedCertificateInternal(String intermediateMount, String signedCertificate) {
    String apiUrl = "/v1/" + intermediateMount + "/intermediate/set-signed";
    JsonObject payload = new JsonObject().put("certificate", signedCertificate);

    LOGGER.info("Installing signed intermediate into mount {} via {}", intermediateMount, apiUrl);

    return vaultHandler.vaultRequest("POST", apiUrl, payload.encode())
      .recover(err -> {
        // Treat not-found/forbidden as non-fatal: return null issuerId
        String msg = err.getMessage() != null ? err.getMessage().toLowerCase() : "";
        if (msg.contains("404") || msg.contains("not found") || msg.contains("permission") || msg.contains("forbidden")) {
          LOGGER.warn("intermediate/set-signed not available or allowed on mount {}: {}; returning null issuerId (non-fatal)", intermediateMount, err.getMessage());
          return Future.succeededFuture(new JsonObject().put("not_supported", true));
        }
        return Future.failedFuture(err);
      })
      .compose(resp -> {
        // If we turned a 404/forbidden into an object with not_supported, return null
        if (resp == null || (resp.containsKey("not_supported") && resp.getBoolean("not_supported"))) {
          return Future.succeededFuture((String) null);
        }

        // Otherwise, attempt to find the issuer id corresponding to the newly-installed certificate.
        Promise<String> p = Promise.promise();
        attemptFindIssuerId(intermediateMount, signedCertificate, 1, 5, 500L, p);
        return p.future();
      });
  }

  // Recursive retry helper to find issuer id after set-signed
  private void attemptFindIssuerId(String mount, String signedCert, int attempt, int maxAttempts, long backoffMillis, Promise<String> promise) {
    // Get issuer ids
    listPkiIssuerIds(mount).onComplete(listAr -> {
      if (listAr.failed()) {
        if (attempt < maxAttempts) {
          LOGGER.debug("listPkiIssuerIds failed on attempt {}/{}: {}; retrying", attempt, maxAttempts, listAr.cause().getMessage());
          vertx.setTimer(backoffMillis, id -> attemptFindIssuerId(mount, signedCert, attempt + 1, maxAttempts, backoffMillis, promise));
        } else {
          LOGGER.warn("listPkiIssuerIds permanently failed after {} attempts: {}; returning null", maxAttempts, listAr.cause().getMessage());
          promise.complete((String) null);
        }
        return;
      }

      List<String> ids = listAr.result();
      if (ids == null || ids.isEmpty()) {
        if (attempt < maxAttempts) {
          vertx.setTimer(backoffMillis, id -> attemptFindIssuerId(mount, signedCert, attempt + 1, maxAttempts, backoffMillis, promise));
        } else {
          promise.complete((String) null);
        }
        return;
      }

      // Try PEM endpoints in parallel (fallback to empty string)
      List<Future<?>> pemFutures = ids.stream()
        .map(id -> getIssuerCertificateViaPem(mount, id).recover(e -> Future.succeededFuture("")))
        .collect(Collectors.toList());

      Future.all(pemFutures).onComplete(pemAll -> {
        if (pemAll.succeeded()) {
          CompositeFuture cf = pemAll.result();
          List<Object> pems = cf.list();
          for (int i = 0; i < pems.size(); i++) {
            String pem = (String) pems.get(i);
            if (pem != null && pem.trim().equals(signedCert.trim())) {
              promise.complete(ids.get(i));
              return;
            }
          }
        } else {
          LOGGER.debug("PEM endpoints composite failed (will try info fallback): {}", pemAll.cause().getMessage());
        }

        // Fallback: fetch issuer info for each issuer and inspect certificate fields
        List<Future<?>> infoFutures = ids.stream()
          .map(id -> getIssuerInfo(mount, id).recover(e -> Future.succeededFuture(new JsonObject())))
          .collect(Collectors.toList());

        Future.all(infoFutures).onComplete(infoAll -> {
          if (infoAll.succeeded()) {
            CompositeFuture cf2 = infoAll.result();
            List<Object> infos = cf2.list();
            for (int i = 0; i < infos.size(); i++) {
              JsonObject info = (JsonObject) infos.get(i);
              if (info != null) {
                JsonObject data = info.getJsonObject("data", new JsonObject());
                String cert = data.getString("certificate", null);
                if (cert != null && cert.trim().equals(signedCert.trim())) {
                  promise.complete(ids.get(i));
                  return;
                }
                if (data.containsKey("ca_chain")) {
                  JsonArray arr = data.getJsonArray("ca_chain");
                  if (arr != null) {
                    for (int x = 0; x < arr.size(); x++) {
                      String entry = arr.getString(x);
                      if (entry != null && entry.trim().equals(signedCert.trim())) {
                        promise.complete(ids.get(i));
                        return;
                      }
                   }
                  }
                }
              }
            }
            // Not found in info fallback
            if (attempt < maxAttempts) {
              vertx.setTimer(backoffMillis, id -> attemptFindIssuerId(mount, signedCert, attempt + 1, maxAttempts, backoffMillis, promise));
            } else {
              LOGGER.warn("Could not locate issuer id for new signed intermediate after {} attempts; returning null", maxAttempts);
              promise.complete((String) null);
            }
          } else {
            // info listing failed
            if (attempt < maxAttempts) {
              LOGGER.debug("Issuer info fetch failed on attempt {}/{}: {}; retrying", attempt, maxAttempts, infoAll.cause().getMessage());
              vertx.setTimer(backoffMillis, id -> attemptFindIssuerId(mount, signedCert, attempt + 1, maxAttempts, backoffMillis, promise));
            } else {
              LOGGER.warn("Issuer info permanently failed after {} attempts: {}; returning null", maxAttempts, infoAll.cause().getMessage());
              promise.complete((String) null);
            }
          }
        });
      });
    });
  }
  
  /**
   * Enhanced getCAChain implementation:
   * - Try raw /ca_chain first (raw PEM)
   * - Fallback to a sequence of common CA endpoints (/ca/pem, /ca, /cert/ca)
   * - If still not found, attempt to assemble a chain by listing issuers and
   *   retrieving issuer/<id>/pem entries (plus root if available).
   *
   * This accepts the PKI mount name (e.g. "pki" or "pulsar_int") and will try to
   * obtain a multi-PEM chain suitable for writing to trust stores.
   */
  public Future<String> getCAChainEnhanced(String pkiMount) {
    LOGGER.info("Attempting enhanced CA chain retrieval for mount: {}", pkiMount);

    String caChainEndpoint = "/v1/" + pkiMount + "/ca_chain";
    // 1) Try ca_chain raw endpoint first
    return vaultHandler.vaultRequestRaw("GET", caChainEndpoint, null)
      .compose(resp -> {
        if (resp != null && resp.contains("-----BEGIN CERTIFICATE-----")) {
          LOGGER.info("Retrieved CA chain from {}", caChainEndpoint);
          return Future.succeededFuture(resp.trim());
        }
        LOGGER.debug("ca_chain endpoint returned no PEM, falling back");
        // 2) Try known root endpoints (ca/pem, ca, cert/ca)
        return getRootCACertificate(pkiMount)
          .recover(err -> {
            LOGGER.debug("Root endpoints failed for {}: {}", pkiMount, err.getMessage());
            // 3) As last resort assemble chain from listing issuers + issuer pem entries
            return listPkiIssuerIds(pkiMount)
              .compose(issuerIds -> {
                if (issuerIds == null || issuerIds.isEmpty()) {
                  LOGGER.warn("No issuers found in mount {} while attempting to assemble CA chain", pkiMount);
                  return Future.failedFuture("No CA chain available from Vault for mount: " + pkiMount);
                }

                List<Future<String>> pemFutures = issuerIds.stream()
                    .map(id -> getIssuerCertificateViaPem(pkiMount, id)
                                 .recover(riErr -> {
                                    LOGGER.debug("Failed to get issuer {} via PEM endpoint: {}", id, riErr.getMessage());
                                    return getIssuerCertificateViaInfo(pkiMount, id)
                                            .recover(iErr -> {
                                              LOGGER.warn("Failed to get issuer {} via info endpoint: {}", id, iErr.getMessage());
                                              return Future.succeededFuture("");
                                            });
                                 }))
                    .collect(Collectors.toList());

                return Future.all(pemFutures)
                  .compose(cf -> {
                    List<Object> results = cf.list();
                    StringBuilder sb = new StringBuilder();
                    int found = 0;
                    for (Object o : results) {
                      String pem = (String)o;
                      if (pem != null && pem.contains("-----BEGIN CERTIFICATE-----")) {
                        if (sb.length() > 0) sb.append("\n");
                        sb.append(pem.trim());
                        found++;
                      }
                    }
                    if (found > 0) {
                      LOGGER.info("Assembled CA chain from {} issuer certificates", found);
                      return Future.succeededFuture(sb.toString());
                    } else {
                      LOGGER.warn("Failed to assemble CA chain from issuers for mount {}", pkiMount);
                      return Future.failedFuture("Failed to assemble CA chain from issuers for mount " + pkiMount);
                    }
                  });
              });
          });
      })
      .recover(err -> {
        LOGGER.warn("Enhanced CA chain retrieval failed for {}: {}", pkiMount, err.getMessage());
        return Future.failedFuture(err);
      });
  }

  public Future<String> getCAChain(String pkiMount) {
    String endpoint = "/v1/" + pkiMount + "/ca_chain";
    
    return vaultHandler.vaultRequestRaw("GET", endpoint, null)
        .map(response -> {
            if (response != null && !response.trim().isEmpty() && 
                response.contains("-----BEGIN CERTIFICATE-----")) {
                LOGGER.info("Retrieved CA chain from {}", endpoint);
                return response;
            } else {
                throw new RuntimeException("Empty or invalid CA chain response");
            }
        });
  }

  /**
   * Count certificates in PEM data
   */
  private int countCertificatesInPem(String pemData) {
    if (pemData == null) return 0;
    
    int count = 0;
    int index = 0;
    while ((index = pemData.indexOf("-----BEGIN CERTIFICATE-----", index)) != -1) {
        count++;
        index += 27; // Length of "-----BEGIN CERTIFICATE-----"
    }
    return count;
  }

  /* =========================
   * KV v2 Helpers
   * ========================= */
  
  public Future<String> readKvV2( String mount, String path, String key ) 
  {
    final String apiUrl = "/v1/" + mount + "/data/" + path;
    return vaultHandler.vaultRequest( "GET", apiUrl, null )
      .compose( json -> 
      {
        try 
        {
          if( json == null || json.isEmpty() ) 
          {
            return Future.failedFuture("Empty response for KV read");
          }
          JsonObject dataOuter = json.getJsonObject("data");
          if( dataOuter == null ) 
          {
            return Future.failedFuture("KV v2 read missing 'data' object");
          }
          JsonObject dataInner = dataOuter.getJsonObject("data");
          if( dataInner == null ) 
          {
            return Future.failedFuture("KV v2 read missing inner 'data' object");
          }
          if( !dataInner.containsKey( key ))
          {
            return Future.failedFuture("KV v2 key '" + key + "' not present");
          }
          String val = dataInner.getString(key);
          return Future.succeededFuture(val);
        } 
        catch( Exception e ) 
        {
          return Future.failedFuture(e);
        }
      });
  }

  public Future<Void> putKvV2( String mount, String path, Map<String, String> data ) 
  {
    final String apiUrl = "/v1/" + mount + "/data/" + path;

    JsonObject inner = new JsonObject();
    if( data != null && !data.isEmpty() ) 
    {
      data.forEach(inner::put);
    }

    JsonObject payload = new JsonObject().put("data", inner);

    return vaultHandler.vaultRequest("POST", apiUrl, payload.encode())
      .map( v -> 
      {
        LOGGER.info("KV v2 write succeeded for {}/{}", mount, path);
        return null;
      });
  }

  public Future<Void> putKvV2( String mount, String path, JsonObject data ) 
  {
    final String apiUrl  = "/v1/" + mount + "/data/" + path;
    JsonObject   payload = new JsonObject().put("data", data != null ? data : new JsonObject());
    return vaultHandler.vaultRequest("POST", apiUrl, payload.encode())
      .map(v -> 
      {
        LOGGER.info("KV v2 write (JsonObject) succeeded for {}/{}", mount, path);
        return null;
      });
  }
  
  /**
   * Wait for Vault processing
   */
  private Future<Void> waitForProcessing(long delayMs) {
    Promise<Void> promise = Promise.promise();
    vertx.setTimer(delayMs, id -> promise.complete());
    return promise.future();
  }

  public Future<List<String>> listPkiIssuerIds( String pkiMount )
  {
    String apiUrl = "/v1/" + pkiMount + "/issuers";

    return vaultHandler.vaultRequest( "LIST", apiUrl, null ).map( response -> 
    {
      JsonObject data = response.getJsonObject( "data" );
      if( data == null )
      {
        LOGGER.warn( "No data field in LIST issuers response for PKI mount {}", pkiMount );
        return new ArrayList<String>();
      }
      
      JsonArray keysArray = data.getJsonArray( "keys" );
      if( keysArray == null )
      {
        LOGGER.warn( "No keys array in LIST issuers response for PKI mount {}", pkiMount );
        return new ArrayList<String>();
      }
      
      List<String> issuerIds = new ArrayList<>();
      for( int i = 0; i < keysArray.size(); i++ )
      {
        issuerIds.add( keysArray.getString( i ) );
      }

      LOGGER.debug( "Found {} issuers in PKI mount {}: {}", issuerIds.size(), pkiMount, issuerIds );
      return issuerIds;
    });
  }

  public Future<JsonObject> getIssuerInfo( String pkiMount, String issuerId )
  {
    String apiUrl = "/v1/" + pkiMount + "/issuer/" + issuerId;

    return vaultHandler.vaultRequest( "GET", apiUrl, null )
      .map( response -> 
      {
        JsonObject data = response.getJsonObject( "data" );
        LOGGER.debug( "Retrieved issuer details for {}", issuerId );
        return data;
      } );
  }

  public Future<String> getDefaultIssuerId( String pkiMount )
  {
    String apiUrl = "/v1/" + pkiMount + "/config/issuers";

    return vaultHandler.vaultRequest( "GET", apiUrl, null )
      .map( response -> 
      {
        JsonObject data = response.getJsonObject( "data" );
        if( data == null )
        {
          LOGGER.debug( "No config data found for PKI mount {}", pkiMount );
          return null;
        }
        
        String defaultId = data.getString( "default", null );
        LOGGER.debug( "Configured default issuer for {}: {}", pkiMount, defaultId );
        return defaultId;
      })
      .recover( err -> 
      {
        LOGGER.debug( "No default issuer configured for {}: {}", pkiMount, err.getMessage() );
        return Future.succeededFuture( null );
      });
  }
   
  public Future<Void> setDefaultIssuer( String pkiMount, String issuerId )
  {
    String apiUrl = "/v1/" + pkiMount + "/config/issuers";

    JsonObject payload = new JsonObject().put( "default", issuerId );

    return vaultHandler.vaultRequest( "POST", apiUrl, payload.encode() ).map( response -> {
      LOGGER.info( "Successfully set default issuer to: {}", issuerId );
      return null;
    } );
  }

  public Future<String> getCABundle()
  {
    return getCAChain( METADATA_PKI_PATH );
  }  

  /**
   * Wait for cluster acks in KV v2 at path secret/data/pulsar/acks/<clusterId>
   * Each ack is expected to contain key "bundle_hash" with the sha256 of the published bundle.
   *
   * This will poll (with backoff) for the presence of all expected acks or fail on timeout.
   */
  /**
   * Wait for cluster acks in KV v2 at path secret/data/pulsar/acks/<clusterId>
   * Each ack is expected to contain key "bundle_hash" with the sha256 of the published bundle.
   *
   * This will poll (with backoff) for the presence of all expected acks or fail on timeout.
   */
  public Future<Void> waitForClusterAcks(String expectedBundleHash, List<String> clusterIds, long timeoutMs) {
    Promise<Void> promise = Promise.promise();
    if (clusterIds == null || clusterIds.isEmpty()) {
      // Nothing to wait for
      promise.complete();
      return promise.future();
    }

    long start = System.currentTimeMillis();
    long initialDelay = 500L;

    // recursive poll helper
    class Poll {
      void run(long delay) {
        vertx.setTimer(delay, tid -> {
          List<Future<?>> checks = new ArrayList<>();
          for (String clusterId : clusterIds) {
            String path = "pulsar/acks/" + clusterId;
            // readKvV2 returns Future<String>; recover to a succeededFuture(null) on error
            checks.add(readKvV2("secret", path, "bundle_hash").recover(err -> Future.succeededFuture((String) null)));
          }

          // Vert.x 5: Future.all accepts List<? extends Future<?>>
          Future<CompositeFuture> all = Future.all(checks);
          all.onComplete(ar -> {
            if (ar.succeeded()) {
              CompositeFuture cf = ar.result();
              boolean allPresent = true;
              for (int i = 0; i < clusterIds.size(); i++) {
                String found = (String) cf.list().get(i);
                if (found == null || !found.equals(expectedBundleHash)) {
                  allPresent = false;
                  break;
                }
              }
              if (allPresent) {
                promise.complete();
                return;
              } else {
                if (System.currentTimeMillis() - start > timeoutMs) {
                  promise.fail("Timeout waiting for cluster acks");
                  return;
                }
                // progressive backoff
                long nextDelay = Math.min(delay * 2, 5000L);
                run(nextDelay);
              }
            } else {
              if (System.currentTimeMillis() - start > timeoutMs) {
                promise.fail("Timeout waiting for cluster acks (composite failed)");
                return;
              }
              long nextDelay = Math.min(delay * 2, 5000L);
              run(nextDelay);
            }
          });
        });
      }
    }

    new Poll().run(initialDelay);
    return promise.future();
  }

  /**
   * Best-effort delete issuer entry in the PKI mount.
   * Vault's API for issuer deletion varies; we attempt a DELETE to the issuer path.
   * This is used by the pruning job; errors are logged and surfaced.
   */
  public Future<Void> deleteIssuer(String pkiMount, String issuerId) {
    if (pkiMount == null || issuerId == null) {
      return Future.failedFuture("invalid args");
    }
    String api = "/v1/" + pkiMount + "/issuer/" + issuerId;

    // vaultRequest returns Future<JsonObject> — map to Void
    return vaultHandler.vaultRequest("DELETE", api, null)
      .map(resp -> {
        LOGGER.info("Deleted issuer {} on mount {}", issuerId, pkiMount);
        return (Void) null;
      })
      .recover(err -> {
        // Log and propagate failure (caller can decide best-effort)
        LOGGER.warn("Failed deleting issuer {}/{} : {}", pkiMount, issuerId, err.getMessage());
        return Future.failedFuture(err);
      });
  }

  public Future<Integer> pruneOldIssuers(String pkiMount, int keepLastN) {
    final int keep = Math.max(1, keepLastN); // effectively-final copy for use in lambdas
    Promise<Integer> p = Promise.promise();

    listPkiIssuerIds(pkiMount).onComplete(listAr -> {
      if (listAr.failed()) {
        p.fail(listAr.cause());
        return;
      }
      List<String> ids = listAr.result();
      if (ids == null || ids.size() <= keep) {
        p.complete(0);
        return;
      }

      int toDelete = ids.size() - keep;
      List<Future<?>> deletes = new ArrayList<>();
      for (int i = 0; i < toDelete; i++) {
        String id = ids.get(i);
        // ensure individual delete failure doesn't short-circuit the group: recover to a succeededFuture(null)
        deletes.add(deleteIssuer(pkiMount, id).recover(err -> {
          LOGGER.warn("Ignored deletion error for issuer {}/{}: {}", pkiMount, id, err.getMessage());
          return Future.succeededFuture((Void) null);
        }));
      }

      // Vert.x 5: Future.all accepts List<? extends Future<?>>
      Future<CompositeFuture> allDeletes = Future.all(deletes);
      allDeletes.onComplete(delAr -> {
        if (delAr.succeeded()) {
          LOGGER.info("Prune completed: attempted to delete {} issuers from {}", toDelete, pkiMount);
        } else {
          LOGGER.warn("Prune completed with some errors; attempted to delete {} issuers from {} (some failed)", toDelete, pkiMount);
        }
        p.complete(toDelete);
      });
    });

    return p.future();
  }

  private String fingerprintSha256FromPem(String pem) {
    if (pem == null) return null;
    try {
        String b64;
        int b = pem.indexOf("-----BEGIN CERTIFICATE-----");
        int e = pem.indexOf("-----END CERTIFICATE-----");
        if (b != -1 && e != -1 && e > b) {
            String block = pem.substring(b + "-----BEGIN CERTIFICATE-----".length(), e);
            b64 = block.replaceAll("\\s+", "");
        } else {
            b64 = pem.replaceAll("\\s+", "");
        }
        byte[] der = Base64.getDecoder().decode(b64);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(der);
        StringBuilder sb = new StringBuilder();
        for (byte by : digest) sb.append(String.format("%02x", by & 0xff));
        return sb.toString();
    } catch (Exception ex) {
        LOGGER.debug("fingerprint error: {}", ex.getMessage());
        return null;
    }
  }

  private Date certificateNotBefore(String pem) {
    try {
        String b64;
        int b = pem.indexOf("-----BEGIN CERTIFICATE-----");
        int e = pem.indexOf("-----END CERTIFICATE-----");
        if (b != -1 && e != -1 && e > b) {
            String block = pem.substring(b + "-----BEGIN CERTIFICATE-----".length(), e);
            b64 = block.replaceAll("\\s+", "");
        } else {
            b64 = pem.replaceAll("\\s+", "");
        }
        byte[] der = Base64.getDecoder().decode(b64);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        return cert.getNotBefore();
    } catch (Exception ignore) {
        return null;
    }
}

/**
 * Find issuer id for a signed intermediate pem. Promise completes with the chosen issuer id or null.
 * - mount: "pulsar_int"
 * - signedPem: the PEM you posted to intermediate/set-signed
 * - attempt/backoff flow is internal (start attempt=1, maxAttempts=8, backoffMillis=500)
 */
  private void findIssuerIdForSignedCert(String mount, String signedPem, Promise<String> promise) {
    final int    maxAttempts    = 8;
    final long   initialBackoff = 500L;
    final String targetFp       = fingerprintSha256FromPem(signedPem);

    class TryFind 
    {
      void run( int attempt, long backoff ) 
      {
        listPkiIssuerIds(mount).onComplete( listAr -> 
        {
          if( listAr.failed() ) 
          {
            if( attempt < maxAttempts ) 
            {
              long next = Math.min(backoff * 2, 5000L);
              LOGGER.debug("list failed attempt {}/{}: {}; retrying in {}ms", attempt, maxAttempts, listAr.cause().getMessage(), next);
              vertx.setTimer(next, id -> run(attempt + 1, next));
            }
            else 
            {
              LOGGER.warn("listPkiIssuerIds failed after {} attempts: {}", maxAttempts, listAr.cause().getMessage());
              promise.complete(null);
            }
       
            return;
          }

          List<String> ids = listAr.result();
          if( ids == null || ids.isEmpty() ) 
          {
            if( attempt < maxAttempts )
            {
              long next = Math.min(backoff * 2, 5000L);
              vertx.setTimer(next, id -> run(attempt + 1, next));
            }
            else 
            {
              promise.complete(null);
            }
            
            return;
          }

          // Single-issuer shortcut
          if( ids.size() == 1 ) 
          {
            LOGGER.debug("Single issuer returned for {}: {}", mount, ids.get(0));
            promise.complete(ids.get(0));
            return;
          }

          // Build PEM futures and aggregate manually (Vert.x 5 compatible)
          List<Future<String>> pemFutures = new ArrayList<>();
          for( String id : ids ) 
          {
            pemFutures.add(getIssuerCertificateViaPem(mount, id).recover(e -> Future.succeededFuture("")));
          }

          aggregateResults(pemFutures).onComplete( pemAll -> 
          {
            if( pemAll.succeeded() ) 
            {
              List<String> pems = pemAll.result();
              for( int i = 0; i < ids.size(); i++ ) 
              {
                String pem = pems.get(i);
                if (pem == null || pem.isBlank()) continue;
                String fp = fingerprintSha256FromPem(pem);
                if (fp != null && targetFp != null && fp.equals(targetFp))
                {
                  promise.complete(ids.get(i));
                  return;
                }
              }
            }

                    // Fallback: fetch issuer info for each id and aggregate
                    List<Future<JsonObject>> infoFutures = new ArrayList<>();
                    for (String id : ids) {
                        infoFutures.add(getIssuerInfo(mount, id).recover(e -> Future.succeededFuture(new JsonObject())));
                    }

                    aggregateResults(infoFutures).onComplete(infoAll -> {
                        if (infoAll.succeeded()) {
                            List<JsonObject> infos = infoAll.result();
                            List<String> fpMatches = new ArrayList<>();
                            List<Map.Entry<String, Date>> nameCandidates = new ArrayList<>(); // (id, notBefore)

                            for (int i = 0; i < ids.size(); i++) {
                                JsonObject info = infos.get(i);
                                if (info == null) continue;
                                JsonObject data = info.getJsonObject("data", new JsonObject());

                                // check certificate field
                                String cert = data.getString("certificate", null);
                                if (cert != null) {
                                    String cfp = fingerprintSha256FromPem(cert);
                                    if (cfp != null && targetFp != null && cfp.equals(targetFp)) {
                                        fpMatches.add(ids.get(i));
                                        continue;
                                    }
                                }

                                // check ca_chain
                                if (data.containsKey("ca_chain")) {
                                    try {
                                        JsonArray arr = data.getJsonArray("ca_chain");
                                        if (arr != null) {
                                            for (int x = 0; x < arr.size(); x++) {
                                                String entry = arr.getString(x);
                                                String efp = fingerprintSha256FromPem(entry);
                                                if (efp != null && targetFp != null && efp.equals(targetFp)) {
                                                    fpMatches.add(ids.get(i));
                                                    break;
                                                }
                                            }
                                            if (fpMatches.contains(ids.get(i))) continue;
                                        }
                                    } catch (Exception ignored) {}
                                }

                                // collect name-based candidates with notBefore for fallback
                                String issuerName = data.getString("issuer_name", null);
                                if (issuerName == null || issuerName.isBlank()) issuerName = data.getString("common_name", null);
                                if (issuerName != null && issuerName.toLowerCase().contains("pulsar intermediate authority")) {
                                    String pickPem = cert;
                                    if ((pickPem == null || pickPem.isBlank()) && data.containsKey("ca_chain")) {
                                        JsonArray arr = data.getJsonArray("ca_chain");
                                        if (arr != null && arr.size() > 0) pickPem = arr.getString(0);
                                    }
                                    Date nb = null;
                                    if (pickPem != null) nb = certificateNotBefore(pickPem);
                                    nameCandidates = new ArrayList<>(); // (id, notBefore)
      }
                            }

                            if (!fpMatches.isEmpty()) {
                                if (fpMatches.size() == 1) {
                                    promise.complete(fpMatches.get(0));
                                    return;
                                } else {
                                    String best = fpMatches.stream()
                                        .max(Comparator.comparing(id -> {
                                            JsonObject info = infos.get(ids.indexOf(id));
                                            JsonObject data = info.getJsonObject("data", new JsonObject());
                                            String cert = data.getString("certificate", null);
                                            if (cert == null && data.containsKey("ca_chain")) {
                                                JsonArray arr = data.getJsonArray("ca_chain");
                                                if (arr != null && arr.size() > 0) cert = arr.getString(0);
                                            }
                                            Date nb = certificateNotBefore(cert);
                                            return nb == null ? new Date(0) : nb;
                                        })).orElse(null);
                                    promise.complete(best);
                                    return;
                                }
                            }

                            if (!nameCandidates.isEmpty()) {
                                nameCandidates.sort((a, b) -> {
                                    Date da = a.getValue() == null ? new Date(0) : a.getValue();
                                    Date db = b.getValue() == null ? new Date(0) : b.getValue();
                                    return db.compareTo(da); // newest first
                                });
                                promise.complete(nameCandidates.get(0).getKey());
                                return;
                            }

                            // retry or give up
                            if (attempt < maxAttempts) {
                                long next = Math.min(backoff * 2, 5000L);
                                vertx.setTimer(next, id -> run(attempt + 1, next));
                            } else {
                                promise.complete(null);
                            }
                        } else {
                            if (attempt < maxAttempts) {
                                long next = Math.min(backoff * 2, 5000L);
                                vertx.setTimer(next, id -> run(attempt + 1, next));
                            } else {
                                promise.complete(null);
                            }
                        }
                    });
                });
            });
        }
    }

    new TryFind().run(1, initialBackoff);
  }

  // Manual aggregator for a list of futures -> Future<List<T>> (works with Vert.x 5.0)
  private <T> Future<List<T>> aggregateResults(List<Future<T>> futures) {
    if (futures == null || futures.isEmpty()) {
        return Future.succeededFuture(Collections.emptyList());
    }
    Promise<List<T>> agg = Promise.promise();
    List<T> results = new ArrayList<>(Collections.nCopies(futures.size(), null));
    AtomicInteger remaining = new AtomicInteger(futures.size());
    for (int i = 0; i < futures.size(); i++) {
        final int idx = i;
        futures.get(i).onComplete(ar -> {
            if (ar.succeeded()) {
                results.set(idx, ar.result());
            } else {
                results.set(idx, null);
            }
            if (remaining.decrementAndGet() == 0) {
                agg.complete(results);
            }
        });
    }
    return agg.future();
  }


  /*****************************************************************************/
  /* Cleanup */

  public void close()
  {
    if (workerExecutor != null) {
        workerExecutor.close();
    }
    if( vaultHandler != null ) {
      vaultHandler.close();
    }
  }
  
  /*****************************************************************************/
  /* DTOs */

  public static class CsrWithKeyId {
      private final String csr;
      private final String keyId;
      
      public CsrWithKeyId(String csr, String keyId) {
          this.csr = csr;
          this.keyId = keyId;
      }
      
      public String getCsr() { return csr; }
      public String getKeyId() { return keyId; }
  }

  /**
   * Container for pre-collected existing certificates
   */
  public static class ExistingCertificates {
      private final List<String> intermediateCertificates;
      private final String rootCertificate;
      
      public ExistingCertificates(List<String> intermediateCertificates, String rootCertificate) {
          this.intermediateCertificates = intermediateCertificates != null ? intermediateCertificates : new ArrayList<>();
          this.rootCertificate = rootCertificate;
      }
      
      public List<String> getIntermediateCertificates() { return intermediateCertificates; }
      public String getRootCertificate() { return rootCertificate; }
  }
}