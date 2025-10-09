package net.projectsync.security.jwt.configuration;

import javax.annotation.PostConstruct;

import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
@Profile("dev") // Only runs in 'dev' profile
public class RedisStartupCleaner {

	private final RedisTemplate<String, String> redisTemplate;

    @PostConstruct
    public void flushRedisOnStartup() {
        System.out.println("[RedisStartupCleaner] Flushing all Redis data on startup...");

        try {
            redisTemplate.getConnectionFactory().getConnection().flushAll();
            System.out.println("[RedisStartupCleaner] Redis flush complete.");
        } catch (Exception e) {
            System.err.println("[RedisStartupCleaner] Failed to flush Redis: " + e.getMessage());
        }
    }
}
