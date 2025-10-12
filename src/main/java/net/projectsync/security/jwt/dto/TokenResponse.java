package net.projectsync.security.jwt.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)	// It tells Jackson not to include fields that are null when serializing the object to JSON			
public class TokenResponse {

	@JsonProperty("access_token")			// When your TokenResponse is returned from a controller, the JSON key will be "access_token" instead of "accessToken"
    private String accessToken;
    private UserDTO user;

    // No-args constructor
    public TokenResponse() {}

    // All-args constructor
    public TokenResponse(String accessToken, UserDTO user) {
        this.accessToken = accessToken;
        this.user = user;
    }

    // Getters
    public String getAccessToken() { return accessToken; }
    public UserDTO getUser() { return user; }

    // Setters (optional, for mutability)
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    public void setUser(UserDTO user) { this.user = user; }
}
