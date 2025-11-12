package net.projectsync.security.jwt.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RedisTemplate<String, String> redisTemplate;

    // TTL for refresh tokens in seconds (7 days)
    private static final long REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60;

    private static final String TOKEN_KEY_PREFIX = "token:";			// token:<token> -> username
    private static final String USERNAME_KEY_PREFIX = "username:";		// username:<username>	-> { tokens }
    private static final String METADATA_KEY_PREFIX = "metadata:";		// metadata:username:token	-> {"issuedAt": "2007-01-01", "device": "windows11", "ip":"127.0.0.1"}

    // Save a refresh token for a user with metadata (device, ip, issuedAt)
    public void saveRefreshToken(String token, String username, String deviceInfo, String ipAddress) {
        if (token == null || username == null) return;

        String tokenKey = TOKEN_KEY_PREFIX + token;
        String usernameKey = USERNAME_KEY_PREFIX + username;
        String metadataKey = METADATA_KEY_PREFIX + username + ":" + token;

        // 1️. Token → Username mapping
        redisTemplate.opsForValue().set(tokenKey, username, REFRESH_TOKEN_TTL, TimeUnit.SECONDS);	// token:<token> -> username

        // 2️. Username → { Tokens }
        redisTemplate.opsForSet().add(usernameKey, tokenKey);										// username:<username>	-> { tokens }
        redisTemplate.expire(usernameKey, REFRESH_TOKEN_TTL, TimeUnit.SECONDS);

        // 3️. Metadata (stored as string key-value pairs)
        Map<String, String> metadata = new HashMap<>();
        metadata.put("issuedAt", Instant.now().toString());
        metadata.put("device", deviceInfo);
        metadata.put("ip", ipAddress);

        redisTemplate.opsForHash().putAll(metadataKey, metadata);									// metadata:username:token	-> {"issuedAt": "2007-01-01", "device": "windows11", "ip":"127.0.0.1"}
        redisTemplate.expire(metadataKey, REFRESH_TOKEN_TTL, TimeUnit.SECONDS);
    }

    // Overloaded version (without device/IP)
    public void saveRefreshToken(String token, String username) {
        saveRefreshToken(token, username, "unknown-device", "unknown-ip");
    }

    // Revoke a single refresh token
    public void revokeSingleRefreshToken(String token) {
        if (token == null) return;

        String tokenKey = TOKEN_KEY_PREFIX + token;
        String username = redisTemplate.opsForValue().get(tokenKey);
        if (username == null) return;

        // 1. Remove token → username
        redisTemplate.delete(tokenKey);																// token:<token> -> username

        // 2. Remove from user’s set
        String usernameKey = USERNAME_KEY_PREFIX + username;
        // redisTemplate.delete(usernameKey);														// remove all tokens in a set
        redisTemplate.opsForSet().remove(usernameKey, tokenKey);									// username:<username>	-> { tokens }
        																							// remove one token in a set

        // 3. Remove metadata
        String metadataKey = METADATA_KEY_PREFIX + username + ":" + token;
        redisTemplate.delete(metadataKey);															// metadata:username:token	-> {"issuedAt": "2007-01-01", "device": "windows11", "ip":"127.0.0.1"}
    }

    // Revoke all refresh tokens for a user
    public void revokeAllRefreshTokensForUser(String username) {
        if (username == null) return;

        String usernameKey = USERNAME_KEY_PREFIX + username;
        Set<String> tokenKeys = Optional.ofNullable(redisTemplate.opsForSet().members(usernameKey)).orElse(Collections.emptySet());
        if (tokenKeys.isEmpty()) return;

        for (String tokenKey : tokenKeys) {
            String token = tokenKey.replace(TOKEN_KEY_PREFIX, "");
            redisTemplate.delete(tokenKey);															// token:<token> -> username
            redisTemplate.delete(METADATA_KEY_PREFIX + username + ":" + token);						// metadata:username:token	-> {"issuedAt": "2007-01-01", "device": "windows11", "ip":"127.0.0.1"}
        }
        																							// username:<username>	-> { tokens }
        redisTemplate.delete(usernameKey);															// remove all tokens in a set
        // redisTemplate.opsForSet().remove(usernameKey, tokenKey);									// remove one token in a set
    }

    // Get metadata for a specific token
    public Map<Object, Object> getTokenMetadata(String username, String token) {
        if (username == null || token == null) return Collections.emptyMap();
        String metadataKey = METADATA_KEY_PREFIX + username + ":" + token;
        
        // Object ip = redisTemplate.opsForHash().get(metadataKey, "ip");					// Get only the IP address
        // Set<Object> fields = redisTemplate.opsForHash().keys("token:john:abcd1234");		// only keys      	-> ["issuedAt", "device", "ip"]
        // List<Object> values = redisTemplate.opsForHash().values("token:john:abcd1234");	// only values   	-> ["2025-11-11T08:30Z", "MacBook", "127.0.0.1"]

        // Get full metadata (keys + values)
        return redisTemplate.opsForHash().entries(metadataKey);								// keys + values	->  { "issuedAt"="2025-11-11T08:30Z", "device"="MacBook", "ip"="127.0.0.1" }
    }

    // Get username for a given refresh token
    public Optional<String> getUsernameForRefreshToken(String token) {
        if (token == null) return Optional.empty();
        String tokenKey = TOKEN_KEY_PREFIX + token;
        String username = redisTemplate.opsForValue().get(tokenKey);
        return Optional.ofNullable(username);
    }

    // Check if user has active tokens
    public boolean hasActiveRefreshTokens(String username) {
        if (username == null) return false;
        String userKey = USERNAME_KEY_PREFIX + username;
        Set<String> tokens = Optional.ofNullable(redisTemplate.opsForSet().members(userKey)).orElse(Collections.emptySet());
        return !tokens.isEmpty();
    }

    // Check if a refresh token is valid (exists)
    public boolean isValidRefreshToken(String token) {
        if (token == null) return false;
        String tokenKey = TOKEN_KEY_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(tokenKey));
    }
}

/*
1. Redis After First Login (From Laptop):
| **Key**                       | **Type** | **Value**                                                                                  |
| ----------------------------- | -------- | ------------------------------------------------------------------------------------------ |
| 'token:token123'              | String   | '"mohan"'                                                                                  |
| 'username:mohan'              | Set      | '{ "value_token:token123" }'                                                               |
| 'metadata:mohan:token123'     | Hash     | 'issuedAt = 2025-11-10T20:25:12Z'<br>'device = Windows 11 - Chrome'<br>'ip = 192.168.1.12' |


2. Redis After Second Login (From Mobile):
| **Key**                       | **Type** | **Value**                                                                                  |
| ----------------------------- | -------- | ------------------------------------------------------------------------------------------ |
| 'token:token123'              | String   | '"mohan"'                                                                                  |
| 'token:token456'              | String   | '"mohan"'                                                                                  |
| 'username:mohan'              | Set      | '{ "value_token:token123", "value_token:token456" }'                                       |
| 'metadata:mohan:token123'     | Hash     | 'issuedAt = 2025-11-10T20:25:12Z'<br>'device = Windows 11 - Chrome'<br>'ip = 192.168.1.12' |
| 'metadata:mohan:token456'     | Hash     | 'issuedAt = 2025-11-10T20:30:55Z'<br>'device = Android - Firefox'<br>'ip = 192.168.1.25'   |

3. When Mohan Logs Out from Laptop:
| **Key**                       | **Type** | **Value**                                                                                |
| ----------------------------- | -------- | ---------------------------------------------------------------------------------------- |
| 'token:token456'              | String   | '"mohan"'                                                                                |
| 'username:mohan'              | Set      | '{ "value_token:token456" }'                                                             |
| 'metadata:mohan:token456'     | Hash     | 'issuedAt = 2025-11-10T20:30:55Z'<br>'device = Android - Firefox'<br>'ip = 192.168.1.25' |
*/

/*
Optional Enhancement — Auto Remove Old Token:
	if (tokens.size() >= maxAllowedDevices) {
	    // remove one old token before adding new one
	    String oldestToken = tokens.iterator().next();
	    redisTemplate.opsForSet().remove(userKey, oldestToken);
	}


Modify to allow up to 2 logins:
	public boolean hasActiveRefreshTokens(String username) {
	    if (username == null) return false;
	    String userKey = USERNAME_KEY_PREFIX + username;
	
	    Set<String> tokens = Optional
	            .ofNullable(redisTemplate.opsForSet().members(userKey))
	            .orElse(Collections.emptySet());
	
	    // Allow maximum 2 devices
	    int maxAllowedDevices = 2;
	
	    return tokens.size() >= maxAllowedDevices;
	}
 */
