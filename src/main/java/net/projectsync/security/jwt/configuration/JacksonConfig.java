package net.projectsync.security.jwt.configuration;

import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;

// ✅ This will fix the Instant serialization` error you saw (JSR-310 types not supported).
@Configuration
public class JacksonConfig {

    /**
     * Customize Spring Boot's default ObjectMapper
     * - Registers JavaTimeModule to support Java 8 date/time types
     * - Disables timestamps to serialize as ISO-8601 strings
     * - Keeps microsecond precision (6 fractional digits) like Spring Boot default
     */
    @Bean
    public Jackson2ObjectMapperBuilderCustomizer jacksonCustomizer() {
        return builder -> {
        	JavaTimeModule javaTimeModule = new JavaTimeModule();
            
            // Custom serializer for Instant to truncate to microseconds (6 digits)
            javaTimeModule.addSerializer(Instant.class, new JsonSerializer<Instant>() {
                @Override
                public void serialize(Instant value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
                    gen.writeString(value.truncatedTo(ChronoUnit.MICROS).toString());
                }
            });
            
            // Register JavaTimeModule for Java 8+ date/time support
            builder.modules(javaTimeModule);
            
            // Disable serialization as timestamps (write as ISO-8601 strings)
            builder.featuresToDisable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        };
    }
}

