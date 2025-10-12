package net.projectsync.security.jwt.actuators;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.stereotype.Component;

// https://localhost:8443/actuator/health
@Component("customRedisHealth") // unique name avoids collision with Spring Boot's RedisHealthIndicator
public class CustomRedisHealthIndicator implements HealthIndicator {

    private final RedisConnectionFactory redisConnectionFactory;

    public CustomRedisHealthIndicator(RedisConnectionFactory redisConnectionFactory) {
        this.redisConnectionFactory = redisConnectionFactory;
    }

    @Override
    public Health health() {
        try (var connection = redisConnectionFactory.getConnection()) {
            String pong = connection.ping();
            return Health.up()
                    .withDetail("ping", pong)
                    .withDetail("info", connection.info("server"))
                    .build();
        } catch (Exception e) {
            return Health.down(e)
                    .withDetail("Redis", "Connection refused or unavailable")
                    .build();
        }
    }
}

/**
 * Redis status will appear inside "components" under 'https://localhost:8443/management/health'
 * If you really want /management/redis, you need to wrap it in a custom @Endpoint(id="redis") instead of a HealthIndicator. 
 * But in most Spring Boot projects, the standard practice is to keep it as a HealthIndicator under /health
 */
/*
| Feature          | `/actuator/health`                                                                                    | `HealthIndicator`           |
| ---------------- | ----------------------------------------------------------------------------------------------------- | --------------------------- |
| Type             | HTTP endpoint                                                                                         | Java component              |
| Purpose          | Expose app health via HTTP                                                                            | Provide custom health logic |
| Aggregation      | Yes (combines all indicators)                                                                         | Individual checks           |
| Security         | Controlled via Spring Security                                                                        | No direct HTTP exposure     |
| Use in Interview | Mention that `/health` exposes combined health, HealthIndicators are how you define individual checks |                             |
*/