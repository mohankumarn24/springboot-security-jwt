package net.projectsync.security.jwt.configuration;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
// @Profile("dev") // Only runs in 'dev' profile
public class RedisStartupCleaner {

	private static final Logger logger = LoggerFactory.getLogger(RedisStartupCleaner.class);
	private final RedisTemplate<String, String> redisTemplate;

    @PostConstruct
    public void flushRedisOnStartup() {
    	logger.warn("[RedisStartupCleaner] Flushing ALL Redis data on startup (dev mode)");

        try {
            // redisTemplate.getConnectionFactory().getConnection().flushAll();
        	RedisConnectionFactory connectionFactory = redisTemplate.getConnectionFactory();
            if (connectionFactory == null) {
            	logger.error("[RedisStartupCleaner] Redis connectionFactory is null, skipping flush");
                return;
            }

            RedisConnection connection = connectionFactory.getConnection();
            connection.flushAll();
            logger.warn("[RedisStartupCleaner] Redis flush complete");
        } catch (Exception e) {
            logger.error("[RedisStartupCleaner] Failed to flush Redis", e);
        }
    }
}
