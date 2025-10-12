package net.projectsync.security.jwt.dto;

import java.time.Instant;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)		// This will avoid null fields in your API responses
public class UserDTO {

	@JsonProperty("user_id")
    private Long id;
    private String username;
    private String role;
    private Instant createdAt;
    private Instant updatedAt;

    // No-args constructor
    public UserDTO() {}

    // All-args constructor
    public UserDTO(Long id, String username, String role, Instant createdAt, Instant updatedAt) {
        this.id = id;
        this.username = username;
        this.role = role;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    // Getters
    public Long getId() {
        return id;
    }

    public String getUsername() { return username; }
    public String getRole() { return role; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    // Setters (optional, for mutability). Ot set the fields as 'final'
    public void setId(Long id) { this.id = id; }
    public void setUsername(String username) { this.username = username; }
    public void setRole(String role) { this.role = role; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
