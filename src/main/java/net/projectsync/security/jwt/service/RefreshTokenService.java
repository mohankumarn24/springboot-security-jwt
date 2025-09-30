package net.projectsync.security.jwt.service;

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

    /**
     * Save a refresh token for a user.
     * Stores the token both as an individual key (token -> username)
     * and adds it to a Redis set for that user (username -> Set<tokens>).
     */
    public void saveToken(String token, String username) {
        // Save token -> username with TTL
        redisTemplate.opsForValue().set(token, username, REFRESH_TOKEN_TTL, TimeUnit.SECONDS);

        // Add token to user's set of tokens
        String key = "refreshTokens:" + username;
        redisTemplate.opsForSet().add(key, token);
        redisTemplate.expire(key, REFRESH_TOKEN_TTL, TimeUnit.SECONDS);
    }

    /**
     * Check if a refresh token is valid.
     */
    public boolean isValid(String token) {
        return redisTemplate.hasKey(token);
    }

    /**
     * Revoke a single token.
     */
    public void revokeToken(String token) {
        String username = redisTemplate.opsForValue().get(token);
        if (username != null) {
            // Remove token from user's set
        	String key = "refreshTokens:" + username;
            redisTemplate.opsForSet().remove(key, token);

            // Delete the token key itself
            redisTemplate.delete(token);
        }
    }

    /**
     * Revoke all tokens for a user (used on logout or forced logout).
     */
    public void revokeTokensForUser(String username) {
    	String key = "refreshTokens:" + username;
        Set<String> tokens = redisTemplate.opsForSet().members(key);
        if (tokens != null) {
            for (String token : tokens) {
                redisTemplate.delete(token); // delete each individual token
            }
            redisTemplate.delete(key); // delete the set of tokens
        }
    }

    // Check if user has any active tokens
    public boolean hasActiveTokens(String username) {
        String key = "refreshTokens:" + username;
        Set<String> tokens = redisTemplate.opsForSet().members(key);
        return tokens != null && !tokens.isEmpty();
    }
}
