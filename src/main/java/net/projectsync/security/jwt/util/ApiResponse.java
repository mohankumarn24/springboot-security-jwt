package net.projectsync.security.jwt.util;

import java.time.Instant;

/**
 * Standard API response wrapper.
 *
 * @param <T> Type of the payload
 */
public class ApiResponse<T> {

	// Made fields final → encourages immutability (good practice for DTOs).
    private final String message;
    
    // Serialize as ISO-8601 string
    // com.fasterxml.jackson.databind.exc.InvalidDefinitionException: Java 8 date/time type `java.time.Instant` not supported by default: add Module "com.fasterxml.jackson.datatype:jackson-datatype-jsr310" to enable handling (through reference chain: net.projectsync.security.jwt.util.ApiResponse["timestamp"])
    private final Instant timestamp;
    // private final OffsetDateTime  timestamp; 
    
    private final T data; // optional payload

    // Constructor
    public ApiResponse(String message, Instant timestamp, T data) {
        this.message = message;
        this.timestamp = timestamp;
        this.data = data;
    }

    // Getters
    public String getMessage() {
        return message;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public T getData() {
        return data;
    }
   
    // Removed setters since usually API responses are immutable.
    
    // Optional factory methods of(...) for quicker creation of responses with the current timestamp.
    public static <T> ApiResponse<T> of(String message, T data) {
        return new ApiResponse<>(message, Instant.now(), data);
    }

    public static <T> ApiResponse<T> of(String message) {
        return new ApiResponse<>(message, Instant.now(), null);
    }
}
