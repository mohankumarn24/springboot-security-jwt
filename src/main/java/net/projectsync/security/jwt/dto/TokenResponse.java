package net.projectsync.security.jwt.dto;

public class TokenResponse {

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
    public String getAccessToken() {
        return accessToken;
    }

    public UserDTO getUser() {
        return user;
    }

    // Setters (optional, for mutability)
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public void setUser(UserDTO user) {
        this.user = user;
    }
}
