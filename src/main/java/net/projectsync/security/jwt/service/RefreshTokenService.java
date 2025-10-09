package net.projectsync.security.jwt.service;

import java.time.Duration;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RedisTemplate<String, String> redisTemplate;

    // TTL for refresh tokens in seconds (7 days)
    private static final long REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60;

    // Save a refresh token for a user 
    public void saveToken(String token, String username) {
        // 1. Save token -> username with TTL (token123 → sachin)
        redisTemplate.opsForValue().set(token, username, REFRESH_TOKEN_TTL, TimeUnit.SECONDS);

        // 2. Add token to user's set (username:sachin → {token123, token456})
        String key = "username:" + username;
        redisTemplate.opsForSet().add(key, token);
        redisTemplate.expire(key, REFRESH_TOKEN_TTL, TimeUnit.SECONDS);	// Apply TTL to a Redis key.
    }

    // Check if a refresh token exists in Redis.
    public boolean tokenExists(String token) {
        return redisTemplate.hasKey(token);
    }

    // Revoke a single token.
    public void revokeToken(String token) {
        String username = redisTemplate.opsForValue().get(token);
        if (username == null) return;

        // remove from set (remove token123 from set username:sachin → {token123, token456})
        String key = "username:" + username;
        redisTemplate.opsForSet().remove(key, token);	// result: username:sachin → {token456}
        
        // remove token
        redisTemplate.delete(token);					// remove token123 → sachin
    }

    // Revoke all refresh tokens for a user.
    public void revokeTokensForUser(String username) {
    	String key = "username:" + username;
        // Optional<Set<String>> tokensOpt = Optional.ofNullable(redisTemplate.opsForSet().members(key));
    	Set<String> tokens = Optional.ofNullable(redisTemplate.opsForSet().members(key)).orElse(Collections.emptySet()); // username:sachin → {token123, token456}

        if (!tokens.isEmpty()) {
            /* delete tokens individually
        	for (String token : tokens) {
                redisTemplate.delete(token); // delete each individual token
            }
            */
        	// or Bulk delete tokens as below
            redisTemplate.delete(tokens);	// deletes the individual token keys (token123, token456)
            
            redisTemplate.delete(key);		// deletes the set itself (username:sachin)
        }
        /**
         * - If you just delete the set (username:sachin), the set itself is gone, but the individual token keys (token123, token456) still exist in Redis.
         * - Those tokens would still be considered valid if you check redisTemplate.hasKey(token123).
         */
    }

    // Check if the user has any active tokens.
    public boolean hasActiveTokens(String username) {
    	String key = "username:" + username;
        Set<String> tokens = Optional.ofNullable(redisTemplate.opsForSet().members(key)).orElse(Collections.emptySet());
        return !tokens.isEmpty();
    }

    // Get username for a given refresh token.
    public Optional<String> getUsernameForToken(String refreshToken) {
        String username = redisTemplate.opsForValue().get(refreshToken);
        return Optional.ofNullable(username);
    }

    // Check if a refresh token is valid (exists in Redis).
    public boolean isValidRefreshToken(String refreshToken) {
        return tokenExists(refreshToken);
    }
    
    // Check if a refresh token is valid.
    public boolean isValid(String token) {
        return redisTemplate.hasKey(token);
    }
}
