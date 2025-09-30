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
import net.projectsync.security.jwt.entity.User;

@Service
public class JwtService {

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.access-expiration-ms}")
	private long accessExpirationMs;

	@Value("${jwt.refresh-expiration-ms}")
	private long refreshExpirationMs;

	// Access token using username and role
	public String generateAccessToken(String username, String role) {
	    Map<String, Object> claims = new HashMap<>();
	    claims.put("role", role);
	    claims.put("type", "access");
	    return createToken(claims, username, accessExpirationMs);
	}

	// Refresh token using username
	public String generateRefreshToken(String username) {
	    Map<String, Object> claims = new HashMap<>();
	    claims.put("type", "refresh");
	    return createToken(claims, username, refreshExpirationMs);
	}

	// Optional overloads for convenience
	public String generateAccessToken(User user) {
		return generateAccessToken(user.getUsername(), user.getRole());
	}

	public String generateRefreshToken(User user) {
		return generateRefreshToken(user.getUsername());
	}

	private String createToken(Map<String, Object> claims, String subject, long ttlMillis) {
		long now = System.currentTimeMillis();
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(now))
				.setExpiration(new Date(now + ttlMillis)).signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	public Claims extractAllClaims(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	public String extractUsername(String token) {
		try {
			return extractAllClaims(token).getSubject();
		} catch (JwtException | IllegalArgumentException e) {
			return null;
		}
	}

	public boolean isRefreshToken(String token) {
		try {
			return "refresh".equals(extractAllClaims(token).get("type", String.class));
		} catch (JwtException e) {
			return false;
		}
	}
}