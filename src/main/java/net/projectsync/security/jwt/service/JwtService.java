package net.projectsync.security.jwt.service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.exception.InvalidJwtTokenException;
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
        claims.put("type", "access");
        claims.put("role", role.name());
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
        try {
            return Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();
		} catch (ExpiredJwtException e) {
			throw new InvalidJwtTokenException("Access token expired", e);
		} catch (MalformedJwtException e) {
			throw new InvalidJwtTokenException("Invalid token", e);
		} catch (SignatureException e) {
			throw new InvalidJwtTokenException("Invalid JWT signature", e);
		} catch (UnsupportedJwtException e) {
			throw new InvalidJwtTokenException("Unsupported JWT token", e);
		} catch (IllegalArgumentException e) {
			throw new InvalidJwtTokenException("JWT token is empty or null", e);
		} catch (JwtException e) {
			throw new InvalidJwtTokenException("Invalid token", e);
		}
    }
    
    // 5️. Extract username (subject) from JWT
    public String extractUsername(String token) {
    	// return extractAllClaims(token).getSubject();
        return extractClaim(token, Claims::getSubject);
    }

    // Extract a specific claim
    public <T> T extractClaim(String token, java.util.function.Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
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
    
    // Validate token (optional utility)
    public boolean isTokenValid(String token, String username) {
        final String tokenUsername = extractUsername(token);
        return (tokenUsername.equals(username) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }
}

