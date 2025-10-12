package net.projectsync.security.jwt.util;

import java.time.Instant;

/**
 * Standard API response wrapper.
 * @param <T> Type of the payload
 */
public class ApiResponse<T> {

	// Made fields final → encourages immutability (good practice for DTOs).
    private final String message;
    
    // Serialize as ISO-8601 string
    private final Instant timestamp;
    // private final OffsetDateTime  timestamp; 
    
    // ApiResponse<String> response = new ApiResponse<>("Logged out", Instant.now(), null);	// T is String (compile-time type).
    // 'data' can be null; T exists at compile-time, appears as "data": null in JSON, no validation needed.
    private final T data; // optional payload

    // Constructor
    public ApiResponse(String message, Instant timestamp, T data) {
        this.message = message;
        this.timestamp = timestamp;
        this.data = data;
    }

    // Getters
    public String getMessage() { return message; }
    public Instant getTimestamp() { return timestamp; }
    public T getData() { return data; }
   
    // Removed setters since usually API responses are immutable.
    
    // Optional factory methods of(...) for quicker creation of responses with the current timestamp.
    public static <T> ApiResponse<T> of(String message, T data) {
        return new ApiResponse<>(message, Instant.now(), data);
    }

    public static <T> ApiResponse<T> of(String message) {
        return new ApiResponse<>(message, Instant.now(), null);
    }
}

/*
 * Notes on generic type T and null values:
 * 
 * - T represents the payload type at compile time (e.g., String, UserDTO, List<UserDTO>).
 * - The 'data' field can be null. This is perfectly valid; T still exists at compile time.
 * - At runtime, due to type erasure, the JVM sees 'data' simply as Object. 
 *   The actual generic type T is not retained at runtime.
 * - When serialized to JSON (e.g., via Jackson), a null 'data' field will appear as:
 *       "data": null
 *   unless configured otherwise.
 * - No additional validation is needed for null 'data', unless your API contract requires it.
 */