package net.projectsync.security.jwt.dto;

import java.time.Instant;

public class ApiResponse<T> {

    private String message;
    private Instant timestamp;
    private T data; // optional payload

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

    // Optional: setters if you need mutability
    public void setMessage(String message) {
        this.message = message;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public void setData(T data) {
        this.data = data;
    }
}
