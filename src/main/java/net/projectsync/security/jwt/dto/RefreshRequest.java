package net.projectsync.security.jwt.dto;

import javax.validation.constraints.NotBlank;

public class RefreshRequest {

    @NotBlank(message = "Refresh token is required")
    private String refreshToken;

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}