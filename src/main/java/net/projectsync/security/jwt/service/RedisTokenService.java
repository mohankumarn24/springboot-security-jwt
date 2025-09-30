package net.projectsync.security.jwt.service;

import java.util.concurrent.TimeUnit;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RedisTokenService {

	private final RedisTemplate<String, String> redisTemplate;

	// Save token with expiration
	public void saveToken(String token, long ttlMillis) {
		redisTemplate.opsForValue().set(token, "VALID", ttlMillis, TimeUnit.MILLISECONDS);
	}

	// Delete token (logout)
	public void deleteToken(String token) {
		redisTemplate.delete(token);
	}

	// Check if token is active
	public boolean isTokenValid(String token) {
		return redisTemplate.hasKey(token);
	}
}
