package acl;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import acl.ServicesACLConfig.PermissionType;

/**
 * Parser that converts script to structured format with intelligent caching
 * Maintains script as single source of truth while providing structured performance
 */
public class ServicesACLParser
{
  private static final Logger LOGGER = LoggerFactory.getLogger(ServicesACLParser.class);
  
  private   final Vertx vertx;
  protected final WorkerExecutor workerExecutor;
  
  // Intelligent caching to avoid re-parsing unchanged scripts
  private final ConcurrentHashMap<String, ServicesACLConfig> parseCache = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, String> scriptHashes = new ConcurrentHashMap<>();
  
//  private static final Pattern GRANT_PERMISSION_PATTERN = Pattern.compile(
//    "bin/pulsar-admin topics grant-permission --actions\\s+(\\w+)\\s+--role\\s+(\\w+)\\s+persistent://([^/]+)/([^/]+)/([^\\s]+)"
//  );

  private static final Pattern GRANT_PERMISSION_PATTERN = Pattern.compile(
      // Example lines:
      // bin/pulsar-admin topics grant-permission --actions produce --role watcher "persistent://metadata/bundle-pull/svc-watcher"
      // Accept optional quotes around the persistent://... argument and allow role names with hyphens/dots
      "bin/pulsar-admin\\s+topics\\s+grant-permission\\s+--actions\\s+(produce|consume)\\s+--role\\s+([^\\s\"]+)\\s+\"?persistent://([^/\\s\"]+)/([^/\\s\"]+)/([^\\s\"]+)\"?",
      Pattern.CASE_INSENSITIVE
    );

  //Replace the simplistic admin-role test with an explicit set:
  private static final Set<String> DEFAULT_ADMIN_ROLES = Set.of( "proxy", "admin", "manager" );

 
  
  public ServicesACLParser(Vertx vertx)
  {
    this.vertx = vertx;
    this.workerExecutor = this.vertx.createSharedWorkerExecutor("cached-acl-parser", 2, 360000);
  }
  
  /**
   * Parse script to structured format with intelligent caching
   * Only re-parses if script content has actually changed
   */
  public Future<ServicesACLConfig> parseFromScript(String setupScript)
  {
    return workerExecutor.executeBlocking(() -> {
      try
      {
        if (setupScript == null || setupScript.trim().isEmpty())
        {
          LOGGER.warn("Empty setup script provided");
          return new ServicesACLConfig();
        }
        
        // Calculate script hash for caching
        String scriptHash = calculateScriptHash(setupScript);
        
        // Check cache first
        ServicesACLConfig cachedConfig = parseCache.get(scriptHash);
        if (cachedConfig != null)
        {
          LOGGER.debug("Using cached parsed configuration (hash: {})", scriptHash.substring(0, 8));
          return cachedConfig;
        }
        
        // Parse script into structured format
        LOGGER.info("Parsing ACL script into structured format");
        ServicesACLConfig config = parseScriptToStructured(setupScript);
        
        // Cache the result
        parseCache.put(scriptHash, config);
        scriptHashes.put("current", scriptHash);
        
        // Clean old cache entries (keep only last 3)
        cleanCache();
        
        LOGGER.info("Parsed script: {} services, {} topics (cached with hash: {})", 
                   config.getServiceCount(), config.getTopicCount(), scriptHash.substring(0, 8));
        
        return config;
      }
      catch (Exception e)
      {
        LOGGER.error("Failed to parse script", e);
        throw new RuntimeException("Script parsing failed", e);
      }
    });
  }
  
  /**
   * Get the current script hash without parsing
   */
  public String getScriptHash(String setupScript)
  {
    return calculateScriptHash(setupScript);
  }
  
  /**
   * Check if script has changed since last parse
   */
  public boolean hasScriptChanged(String setupScript)
  {
    String newHash = calculateScriptHash(setupScript);
    String currentHash = scriptHashes.get("current");
    return !newHash.equals(currentHash);
  }
  
  /**
   * Get configuration difference between scripts efficiently
   */
  public Future<ACLConfigDifference> getScriptDifference(String oldScript, String newScript)
  {
    return workerExecutor.executeBlocking(() -> {
      try
      {
        // Parse both scripts to structured format (using cache)
        ServicesACLConfig oldConfig = parseFromScript(oldScript).toCompletionStage().toCompletableFuture().get();
        ServicesACLConfig newConfig = parseFromScript(newScript).toCompletionStage().toCompletableFuture().get();
        
        // Calculate structured difference
        return newConfig.calculateDifference(oldConfig);
      }
      catch (Exception e)
      {
        throw new RuntimeException("Failed to calculate script difference", e);
      }
    });
  }
  
  /**
   * Parse script into structured configuration
   */
  private ServicesACLConfig parseScriptToStructured(String setupScript)
  {
    ServicesACLConfig config = new ServicesACLConfig();
    
    String[] lines = setupScript.split("\n");
    int permissionCount = 0;
    
    for (String line : lines)
    {
      if (parseSinglePermissionLine(line.trim(), config))
      {
        permissionCount++;
      }
    }
    
    LOGGER.debug("Parsed {} permissions from script", permissionCount);
    return config;
  }

  /**
   * Parse a single permission line from script with improved matching and diagnostics
   */
  private boolean parseSinglePermissionLine(String line, ServicesACLConfig config)
  {
    // Skip blank lines and comments
    if (line == null || line.isBlank() || line.startsWith("#")) {
      LOGGER.debug("Skipping empty/comment line");
      return false;
    }

    Matcher matcher = GRANT_PERMISSION_PATTERN.matcher(line);
    if (!matcher.find())
    {
      LOGGER.debug("Line did not match permission pattern: '{}'", line);
      return false; // Not a permission line
    }

    String action = matcher.group(1).toLowerCase(Locale.ROOT);
    String service = matcher.group(2);
    String tenant = matcher.group(3);
    String namespace = matcher.group(4);
    String topic = matcher.group(5);

    // Defensive: strip optional quotes (if any crept in)
    service   = stripSurroundingQuotes( service   );
    tenant    = stripSurroundingQuotes( tenant    );
    namespace = stripSurroundingQuotes( namespace );
    topic     = stripSurroundingQuotes( topic     );

    LOGGER.debug("Extracted components - action: '{}', service: '{}', tenant: '{}', namespace: '{}', topic: '{}'",
                 action, service, tenant, namespace, topic);

    // Skip administrative roles (exact matches or containing configured roles)
    if (isAdministrativeRole(service))
    {
      LOGGER.debug("Skipping administrative role: {}", service);
      return false;
    }

    String fullTopicName = String.format("%s/%s/%s", tenant, namespace, topic);

    if ("produce".equals(action))
    {
      LOGGER.debug("Adding PRODUCE permission: service='{}' -> topic='{}'", service, fullTopicName);
      config.addPermission(service, fullTopicName, PermissionType.PRODUCE);
    }
    else if ("consume".equals(action))
    {
      LOGGER.debug("Adding CONSUME permission: service='{}' -> topic='{}'", service, fullTopicName);
      config.addPermission(service, fullTopicName, PermissionType.CONSUME);
    }
    else
    {
      LOGGER.warn("Unknown action: '{}'", action);
      return false;
    }

    return true;
  }

  private static String stripSurroundingQuotes(String s) {
    if (s == null) return null;
    s = s.trim();
    if (s.length() >= 2 && ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'")))) {
      return s.substring(1, s.length() - 1);
    }
    return s;
  }

  /**
   * Calculate deterministic hash of script content
   */
  private String calculateScriptHash(String script)
  {
    try
    {
      // Normalize script for consistent hashing
      String normalizedScript = normalizeScript(script);
      
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(normalizedScript.getBytes());
      return Base64.getEncoder().encodeToString(hash);
    }
    catch (Exception e)
    {
      LOGGER.error("Failed to calculate script hash", e);
      return String.valueOf(script.hashCode());
    }
  }
 
  
  /**
   * Normalize script for consistent hashing (remove whitespace variations, etc.)
   */
  private String normalizeScript(String script)
  {
    return script.replaceAll("\\s+", " ")  // Normalize whitespace
                 .replaceAll("(?m)^\\s*$", "")  // Remove empty lines
                 .trim();
  }
  
  /**
   * Clean old cache entries to prevent memory leaks
   */
  private void cleanCache()
  {
    if (parseCache.size() > 3)
    {
      // Keep only the 3 most recent entries
      String currentHash = scriptHashes.get("current");
      parseCache.entrySet().removeIf(entry -> !entry.getKey().equals(currentHash));
      
      LOGGER.debug("Cleaned parse cache, kept {} entries", parseCache.size());
    }
  }
  

  private boolean isAdministrativeRole( String roleName ) 
  {
    if (roleName == null) return false;

    String lower = roleName.toLowerCase( Locale.ROOT );
 
    // exact match OR contains a configured admin token
    for( String admin : DEFAULT_ADMIN_ROLES ) 
    {
      if( lower.equals(admin ) || lower.contains( admin )) 
      {
        return true;
      }
    }
 
    return false;
  } 
  
  /**
   * Clear cache (useful for testing or memory cleanup)
   */
  public void clearCache()
  {
    parseCache.clear();
    scriptHashes.clear();
    LOGGER.info("Cleared parser cache");
  }
  
  /**
   * Get cache statistics
   */
  public CacheStats getCacheStats()
  {
    return new CacheStats(parseCache.size(), scriptHashes.size());
  }
  
  public void close()
  {
    clearCache();
    if (workerExecutor != null)
    {
      workerExecutor.close();
      LOGGER.info("Cached Structured ACL Parser closed");
    }
  }
  
  public static class CacheStats
  {
    private final int parseCacheSize;
    private final int hashCacheSize;
    
    public CacheStats(int parseCacheSize, int hashCacheSize)
    {
      this.parseCacheSize = parseCacheSize;
      this.hashCacheSize = hashCacheSize;
    }
    
    public int getParseCacheSize() { return parseCacheSize; }
    public int getHashCacheSize() { return hashCacheSize; }
    
    @Override
    public String toString()
    {
      return String.format("CacheStats{parseCache=%d, hashCache=%d}", parseCacheSize, hashCacheSize);
    }
  }
}