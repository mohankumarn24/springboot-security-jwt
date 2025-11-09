package net.projectsync.security.jwt.configuration;

import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.ser.InstantSerializer;
import com.fasterxml.jackson.datatype.jsr310.ser.OffsetDateTimeSerializer;
import com.fasterxml.jackson.datatype.jsr310.ser.ZonedDateTimeSerializer;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import com.fasterxml.jackson.databind.SerializationFeature;

// This will fix the Instant serialization` error you saw (JSR-310 types not supported).
// added to support 'Instant' datattype serialization in APiResponse
@Configuration
public class JacksonConfig {

    /**
     * Customize (Spring Boot's default ObjectMapper) Jackson's ObjectMapper:
     * - Registers JavaTimeModule to support Java 8+ date/time types
     * - Serializes all dates as ISO-8601 strings (no timestamps)
     * - Disables timestamps to serialize as ISO-8601 strings
     * - Keeps microsecond precision (6 fractional digits) like Spring Boot default
     */
	
	// Use Jackson2ObjectMapperBuilderCustomizer to configure the Spring-managed ObjectMapper globally
	// Avoid new ObjectMapper() unless you intentionally want a separate instance
	// Any global Java time or serializer settings should go in the customizer for consistent behavior
    @Bean
    public Jackson2ObjectMapperBuilderCustomizer jacksonCustomizer() {
    	
    	return new Jackson2ObjectMapperBuilderCustomizer() {
			
			@Override
			public void customize(Jackson2ObjectMapperBuilder builder) {
	        	// Registers JavaTimeModule. Needed for proper serialization/deserialization of Java 8 date/time types (Instant, LocalDateTime, OffsetDateTime, etc.).
	        	// Without it, Jackson may fail to serialize Instant or write timestamps as numeric epoch values.
	        	JavaTimeModule javaTimeModule = new JavaTimeModule();
	            
	        	// Use built-in ISO serializers for Java 8 date/time types. Ex: InstantSerializer (Jackson). ISO-8601 output
	        	javaTimeModule.addSerializer(Instant.class, InstantSerializer.INSTANCE);
	        	javaTimeModule.addSerializer(OffsetDateTime.class, OffsetDateTimeSerializer.INSTANCE);
	        	javaTimeModule.addSerializer(ZonedDateTime.class, ZonedDateTimeSerializer.INSTANCE);
	        	
	            // Alternative: Custom json serializer for Instant to truncate to microseconds (6 digits)
	        	/*
	            javaTimeModule.addSerializer(Instant.class, new JsonSerializer<Instant>() {
	                @Override
	                public void serialize(Instant value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
	                    gen.writeString(value.truncatedTo(ChronoUnit.MICROS).toString());
	                }
	            });
	            */
	            
	        	// Attach/register the module for Java 8+ date/time support
	        	builder.modules(javaTimeModule);
	            
	            // Force ISO-8601 (not timestamps) -> Prevents Jackson from writing dates as numeric timestamps (epoch milliseconds).
	            // Ensure dates are written as ISO-8601 strings, not numeric timestamps
	        	// "createdDate": 1699512000000 -> "createdDate": "2025-11-09T14:30:00"
	        	builder.featuresToDisable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
			}
		};
    }
}

/*
@Bean
public Jackson2ObjectMapperBuilderCustomizer jacksonCustomizer() {
    return builder -> {
        builder.modules(new JavaTimeModule());
        builder.featuresToDisable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    };
}
*/



/*
| Feature                 | Custom JsonSerializer (truncate) | InstantSerializer (Jackson)       |
| ----------------------- | -------------------------------- | --------------------------------- |
| ISO-8601 output         | ✅                                | ✅                                 |
| Microsecond precision   | ✅ (explicit)                     | ❌ (outputs full nanoseconds)      |
| Nanosecond precision    | ❌                                | ✅ (if `Instant` has it)           |
| Reuse / maintainability | Less reusable, manual            | Highly reusable, Jackson-native   |
| Flexibility             | High (you control truncation)    | Medium (uses standard formatting) |


- Key takeaway:
 	-- You’re not directly touching ObjectMapper, but your customizer indirectly affects the global ObjectMapper that Spring uses.
 	-- Any @Autowired ObjectMapper or Spring MVC REST response serialization automatically uses your customizations.
 - Creating new ObjectMapper() manually bypasses your customizer — it won’t have your modules or feature changes.
*/