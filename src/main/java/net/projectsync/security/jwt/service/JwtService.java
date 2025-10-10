package net.projectsync.security.jwt.service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.model.Role;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final RefreshTokenService refreshTokenService;

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-expiration-ms}")
    private long accessExpirationMs;

    @Value("${jwt.refresh-expiration-ms}")
    private long refreshExpirationMs;

    // 1️. Generate an access token with username + role claims
    public String generateAccessToken(String username, Role role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", role.name());
        claims.put("type", "access");
        return createToken(claims, username, accessExpirationMs);
    }

    // 2️. Generate a refresh token (minimal claims)
    public String generateRefreshToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");
        return createToken(claims, username, refreshExpirationMs);
    }

    // 3️. Generic token creation
    private String createToken(Map<String, Object> claims, String subject, long ttlMillis) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + ttlMillis))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    // 4️. Extract all claims from JWT (validates signature & expiration)
    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }

    // 5️. Extract username (subject) from JWT
    public String extractUsername(String token) {
        try {
            return extractAllClaims(token).getSubject();
        } catch (JwtException | IllegalArgumentException e) {
            return null; // token invalid or expired
        }
    }

    // 6️. Validate refresh token (type + Redis existence)
    public boolean isValidRefreshToken(String token) {
        try {
            // a. Check token type
            String tokenType = extractAllClaims(token).get("type", String.class);
            if (!"refresh".equals(tokenType)) return false;

            // b. Check Redis to prevent reuse
            return refreshTokenService.isValidRefreshToken(token);

        } catch (JwtException | IllegalArgumentException e) {
            return false; // invalid, expired, or tampered
        }
    }
}


