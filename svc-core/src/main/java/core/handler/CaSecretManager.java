package core.handler;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.vertx.core.Future;
import io.vertx.core.Promise;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import core.model.CaBundle;

/**
 * Manages CA certificate bundles in Kubernetes secrets.
 *
 * Changes:
 * - Keep both "ca-bundle.crt" and a legacy "ca.crt" entry in the secret to ensure compatibility
 *   with consumers that expect the filename/key "ca.crt".
 * - Sanitize labels and keep human-readable timestamps in annotations.
 */
public class CaSecretManager
{
  private static final Logger LOGGER = LoggerFactory.getLogger(CaSecretManager.class);

  // Standard secret data keys for CA certificates
  private static final String CA_BUNDLE_KEY    = "ca-bundle.crt";
  private static final String LEGACY_CA_KEY    = "ca.crt";           // add legacy-compatible key
  private static final String CA_VERSION_KEY   = "ca-version";
  private static final String CA_EPOCH_KEY     = "ca-epoch";
  private static final String LAST_UPDATED_KEY = "last-updated";

  private final KubernetesClient kubeClient;
  private final String namespace;
  private final String serviceId;
  private final String caSecretName;

  public CaSecretManager(KubernetesClient kubeClient, String namespace, String serviceId)
  {
    this.kubeClient   = kubeClient;
    this.namespace    = namespace;
    this.serviceId    = serviceId;
    this.caSecretName = generateCaSecretName(serviceId);

    LOGGER.info("CaSecretManager initialized - namespace: {}, serviceId: {}, secretName: {}",
                namespace, serviceId, caSecretName);
  }

  public void updateCaSecret(CaBundle caBundle)
    throws Exception
  {
    try {
        LOGGER.info("Updating CA secret with new bundle - Version: {}, Epoch: {}",
                   caBundle.getCaVersion(), caBundle.getCaEpochNumber());

        String caBundleStr = caBundle.getCaBundle();

        // Validate PEM format
        if (!isValidPemBundle(caBundleStr)) {
            throw new IllegalArgumentException("Invalid PEM format in CA bundle");
        }

        // Use UTF-8 bytes directly (we store base64-encoded data in secret.data)
        byte[] caBundleBytes = caBundleStr.getBytes(StandardCharsets.UTF_8);

        // Prepare secret data (repository pattern: pre-encode values)
        Map<String, String> secretData = new HashMap<>();
        String caBundleB64 = Base64.getEncoder().encodeToString(caBundleBytes);
        secretData.put(CA_BUNDLE_KEY, caBundleB64);
        // Add legacy "ca.crt" key so mounts or consumers looking for that filename will still work
        secretData.put(LEGACY_CA_KEY, caBundleB64);

        secretData.put(CA_VERSION_KEY, Base64.getEncoder().encodeToString(caBundle.getCaVersion().getBytes(StandardCharsets.UTF_8)));
        secretData.put(CA_EPOCH_KEY, Base64.getEncoder().encodeToString(String.valueOf(caBundle.getCaEpochNumber()).getBytes(StandardCharsets.UTF_8)));
        secretData.put(LAST_UPDATED_KEY, Base64.getEncoder().encodeToString(caBundle.getTimestamp().toString().getBytes(StandardCharsets.UTF_8)));

        // Prepare labels and sanitize values to meet Kubernetes label constraints.
        Map<String, String> labels = new HashMap<>();
        labels.put("app.kubernetes.io/component", "ca-bundle");
        labels.put("app.kubernetes.io/managed-by", "metadata-service");
        labels.put("service-id", sanitizeLabelValue(serviceId));
        labels.put("ca-version", sanitizeLabelValue(caBundle.getCaVersion()));
        labels.put("ca-epoch", sanitizeLabelValue(String.valueOf(caBundle.getCaEpochNumber())));

        // Prepare annotations for free-form metadata (timestamp, event type etc.)
        Map<String, String> annotations = new HashMap<>();
        annotations.put("ca.rotation/server-id", caBundle.getServerId());
        annotations.put("ca.rotation/event-type", caBundle.getEventType());
        annotations.put("ca.rotation/timestamp", caBundle.getTimestamp().toString());
        annotations.put("ca.rotation/epoch", String.valueOf(caBundle.getCaEpochNumber()));

        // Check if secret exists and update/create accordingly
        Secret existingSecret = kubeClient.secrets()
                                          .inNamespace(namespace)
                                          .withName(caSecretName)
                                          .get();

        if (existingSecret != null) {
            LOGGER.info("Updating existing CA secret: {}", caSecretName);

            Secret updatedSecret = new SecretBuilder(existingSecret)
                .editMetadata()
                    .addToLabels(labels)
                    .addToAnnotations(annotations)
                .endMetadata()
                .withData(secretData)
                .build();

            kubeClient.secrets().inNamespace(namespace).resource(updatedSecret).update();
        } else {
            LOGGER.info("Creating new CA secret: {}", caSecretName);

            Secret newSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(caSecretName)
                    .withNamespace(namespace)
                    .withLabels(labels)
                    .withAnnotations(annotations)
                .endMetadata()
                .withType("Opaque")
                .withData(secretData)
                .build();

            kubeClient.secrets().inNamespace(namespace).resource(newSecret).create();
        }

        LOGGER.info("Successfully updated CA secret: {} with version: {}", caSecretName, caBundle.getCaVersion());

    } catch (Exception e) {
        LOGGER.error("Failed to update CA secret: {}", caSecretName, e);
        throw e;
    }
  }

  private boolean isValidPemBundle( String pemData )
  {
    if( pemData == null || pemData.trim().isEmpty() )
    {
      return false;
    }

    // Check for PEM certificate markers
    return pemData.contains("-----BEGIN CERTIFICATE-----") &&
           pemData.contains("-----END CERTIFICATE-----");
  }

  /**
   * Get the current CA bundle from the secret
   */
  public Future<CaBundle> getCurrentCaBundle()
  {
    Promise<CaBundle> promise = Promise.promise();

    try
    {
      Secret caSecret = kubeClient.secrets()
                                  .inNamespace(namespace)
                                  .withName(caSecretName)
                                  .get();

      if (caSecret == null)
      {
        promise.fail(new RuntimeException("CA secret not found: " + caSecretName));
        return promise.future();
      }

      Map<String, String> data = caSecret.getData();
      if (data == null)
      {
        promise.fail(new RuntimeException("CA secret has no data: " + caSecretName));
        return promise.future();
      }

      // Try canonical key first, then fall back to legacy key
      String caBundleB64    = data.get(CA_BUNDLE_KEY);
      if (caBundleB64 == null) {
          caBundleB64 = data.get(LEGACY_CA_KEY);
      }
      String caVersionB64   = data.get(CA_VERSION_KEY);
      String caEpochB64     = data.get(CA_EPOCH_KEY);

      if (caBundleB64 == null || caVersionB64 == null)
      {
        promise.fail(new RuntimeException("CA secret missing required data fields"));
        return promise.future();
      }

      // Decode the data
      String caVersion = new String( Base64.getDecoder().decode( caVersionB64 ), StandardCharsets.UTF_8 );
      long caEpoch = caEpochB64 != null ?
        Long.parseLong(new String(Base64.getDecoder().decode( caEpochB64 ), StandardCharsets.UTF_8)) : 0;

      // Get metadata from annotations (defensive null checks)
      Map<String, String> annotations = caSecret.getMetadata() != null ? caSecret.getMetadata().getAnnotations() : null;
      String serverId     = annotations != null && annotations.get("ca.rotation/server-id") != null ? annotations.get("ca.rotation/server-id") : "unknown";
      String eventType    = annotations != null && annotations.get("ca.rotation/event-type") != null ? annotations.get("ca.rotation/event-type") : "CA_ROTATION";
      String timestampStr = annotations != null && annotations.get("ca.rotation/timestamp") != null ? annotations.get("ca.rotation/timestamp") : Instant.now().toString();

      // Create CaBundle object
      CaBundle caBundle = new CaBundle( serverId,
        java.time.Instant.parse(timestampStr),
        caEpoch,
        eventType,
        caBundleB64, // Keep as base64 since that's what CaBundle expects
        caVersion
      );

      LOGGER.info("Retrieved current CA bundle - Version: {}, Epoch: {}", caVersion, caEpoch);
      promise.complete(caBundle);
    }
    catch (Exception e)
    {
      LOGGER.error("Failed to get current CA bundle from secret: {}", caSecretName, e);
      promise.fail(e);
    }

    return promise.future();
  }

  /**
   * Check if CA secret exists
   */
  public boolean caSecretExists()
  {
    try
    {
      Secret secret = kubeClient.secrets()
                                .inNamespace(namespace)
                                .withName(caSecretName)
                                .get();
      return secret != null;
    }
    catch (Exception e)
    {
      LOGGER.error("Error checking if CA secret exists: {}", caSecretName, e);
      return false;
    }
  }

  /**
   * Get the CA secret name for this service
   */
  public String getCaSecretName()
  {
    return caSecretName;
  }

  /**
   * Generate standardized CA secret name based on service ID
   */
  private String generateCaSecretName(String serviceId)
  {
    // Follow Kubernetes naming conventions
    return String.format("%s-ca-bundle", serviceId.toLowerCase());
  }

  /**
   * Delete the CA secret (useful for cleanup or testing)
   */
  public Future<Void> deleteCaSecret()
  {
    Promise<Void> promise = Promise.promise();

    try
    {
      boolean deleted = kubeClient.secrets()
                                  .inNamespace(namespace)
                                  .withName(caSecretName)
                                  .delete()
                                  .size() > 0;

      if (deleted)
      {
        LOGGER.info("Successfully deleted CA secret: {}", caSecretName);
        promise.complete();
      }
      else
      {
        LOGGER.warn("CA secret not found for deletion: {}", caSecretName);
        promise.complete(); // Not an error if it doesn't exist
      }
    }
    catch (Exception e)
    {
      LOGGER.error("Failed to delete CA secret: {}", caSecretName, e);
      promise.fail(e);
    }

    return promise.future();
  }

  /**
   * List all CA secrets in the namespace (useful for monitoring)
   */
  public Map<String, String> listCaSecrets()
  {
    Map<String, String> caSecrets = new HashMap<>();

    try
    {
      kubeClient.secrets()
                .inNamespace(namespace)
                .withLabel("app.kubernetes.io/component", "ca-bundle")
                .list()
                .getItems()
                .forEach(secret -> {
                    String secretName = secret.getMetadata().getName();
                    Map<String, String> lbls = secret.getMetadata().getLabels() != null ? secret.getMetadata().getLabels() : Map.of();
                    String serviceIdLabel = lbls.getOrDefault("service-id", "unknown");
                    String caVersion = lbls.getOrDefault("ca-version", "unknown");

                    caSecrets.put(secretName, String.format( "Service: %s, Version: %s",
                                                             serviceIdLabel, caVersion));
                 });

      LOGGER.debug("Found {} CA secrets in namespace: {}", caSecrets.size(), namespace);
    }
    catch (Exception e)
    {
      LOGGER.error("Failed to list CA secrets in namespace: {}", namespace, e);
    }

    return caSecrets;
  }

  /**
   * Close and cleanup resources
   */
  public void close()
  {
    // Currently no resources to close, but method provided for future use
    LOGGER.debug("CaSecretManager closed for service: {}", serviceId);
  }

  /**
   * Sanitize a value so it is safe to use as a Kubernetes label value.
   * Kubernetes label values must match '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?'
   * This method replaces invalid characters with '-', collapses repeated '-', and trims
   * leading/trailing non-alphanumerics. If result is empty, returns "v1".
   */
  private static String sanitizeLabelValue(String val) {
    if (val == null) return "v1";
    // Replace disallowed characters with '-'
    String s = val.replaceAll("[^A-Za-z0-9_.-]", "-");
    // Collapse multiple dashes
    s = s.replaceAll("-{2,}", "-");
    // Trim leading/trailing non-alphanumeric characters
    s = s.replaceAll("^[^A-Za-z0-9]+", "");
    s = s.replaceAll("[^A-Za-z0-9]+$", "");
    if (s.isEmpty()) s = "v1";
    // Ensure length <= 63 (cut if necessary)
    if (s.length() > 63) s = s.substring(0, 63);
    return s;
  }
}