package net.projectsync.security.jwt.configuration;

import javax.annotation.PostConstruct;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class RedisStartupCleaner {

	private final RedisTemplate<String, String> redisTemplate;

	@PostConstruct
	public void flushRedisOnStartup() {
		System.out.println("Flushing all Redis data on startup...");
		redisTemplate.getConnectionFactory().getConnection().flushAll();
		System.out.println("Redis flush complete.");
	}
}
