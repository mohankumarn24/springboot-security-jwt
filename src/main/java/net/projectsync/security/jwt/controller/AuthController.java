package net.projectsync.security.jwt.controller;

import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.dto.AuthRequest;
import net.projectsync.security.jwt.dto.AuthResponse;
import net.projectsync.security.jwt.dto.RefreshRequest;
import net.projectsync.security.jwt.dto.SignupRequest;
import net.projectsync.security.jwt.entity.User;
import net.projectsync.security.jwt.model.Role;
import net.projectsync.security.jwt.repository.UserRepository;
import net.projectsync.security.jwt.service.JwtService;
import net.projectsync.security.jwt.service.RefreshTokenService;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;

    private static final String COOKIE_PATH = "/api/auth"; // sends cookie to /api/auth/refresh and /api/auth/logout
    private static final long REFRESH_COOKIE_MAX_AGE = 7 * 24 * 60 * 60; // 7 days
    
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("Username already exists");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(encoder.encode(request.getPassword()));
        user.setRole(Role.valueOf(request.getRole().toUpperCase())); // store role as string: USER or ADMIN
        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/signin")
    public ResponseEntity<Map<String, String>> signin(@RequestBody AuthRequest request, HttpServletResponse response) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username"));

        if (!encoder.matches(request.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid password");
        }

        // Check if user already logged in
        // Prevent multiple logins if needed
        if (refreshTokenService.hasActiveTokens(user.getUsername())) {
        	throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User already logged in");
        } 
        
        // Generate tokens
        String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String refreshToken = jwtService.generateRefreshToken(user.getUsername());

        // Save refresh token in Redis
        refreshTokenService.saveToken(refreshToken, user.getUsername());

        // Set refresh token in HttpOnly, Secure cookie
        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true)
                .path(COOKIE_PATH)
                .maxAge(REFRESH_COOKIE_MAX_AGE)
                .sameSite("Strict")
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
        
        // return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
        return ResponseEntity.ok(Map.of("accessToken", accessToken));
        
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(HttpServletRequest request, HttpServletResponse response) {
        // String oldToken = request.getRefreshToken();
    	// String username = jwtService.extractUsername(oldToken);
    	
        // Read refresh token from cookie
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No refresh token provided");
        }

        String oldRefreshToken = Arrays.stream(cookies)
        								.filter(c -> "refreshToken".equals(c.getName()))
        								.map(Cookie::getValue)
        								.findFirst()
        								.orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No refresh token provided"));

        String username = jwtService.extractUsername(oldRefreshToken);

        // Validate old refresh token
        if (username == null || !jwtService.isRefreshToken(oldRefreshToken) || !refreshTokenService.isValid(oldRefreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
        }

        // Revoke old refresh token
        refreshTokenService.revokeToken(oldRefreshToken);

        // Generate new access token and refresh token
        User user = userRepository
        				.findByUsername(username)
        				.orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String newRefreshToken = jwtService.generateRefreshToken(user.getUsername());

        // Save new refresh token
        refreshTokenService.saveToken(newRefreshToken, username);
        
        // Set new refresh token in cookie
        ResponseCookie cookie = ResponseCookie.from("refreshToken", newRefreshToken)
                .httpOnly(true)
                .secure(true)
                .path(COOKIE_PATH)
                .maxAge(REFRESH_COOKIE_MAX_AGE)
                .sameSite("Strict")
                .build();
        response.addHeader("Set-Cookie", cookie.toString());        

        // return ResponseEntity.ok(new AuthResponse(newAccessToken, newRefreshToken));
        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request, HttpServletResponse response) {
    	
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "message", "User already logged out",
                            "timestamp", Instant.now()
                    ));
        }

        Optional<Cookie> refreshCookie = Arrays.stream(cookies)
                								.filter(c -> "refreshToken".equals(c.getName()))
                								.findFirst();

        if (refreshCookie.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "message", "User already logged out",
                            "timestamp", Instant.now()
                    ));
        }

        String refreshToken = refreshCookie.get().getValue();
        String username = jwtService.extractUsername(refreshToken);

        if (username == null || !refreshTokenService.hasActiveTokens(username)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "message", "User already logged out",
                            "timestamp", Instant.now()
                    ));
        }

        // Revoke all tokens
        refreshTokenService.revokeTokensForUser(username);

        // Clear the cookie
        ResponseCookie clearedCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .path(COOKIE_PATH)
                .maxAge(0)
                .sameSite("Strict")
                .build();
        response.addHeader("Set-Cookie", clearedCookie.toString());

        return ResponseEntity.ok(Map.of(
                "message", "Logged out successfully",
                "timestamp", Instant.now()
        ));
        
    	/* OLD CODE
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String accessToken = authHeader.substring(7);
            String username = jwtService.extractUsername(accessToken);

            // Check if user is already logged out
            if (!refreshTokenService.hasActiveTokens(username)) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("message", "User already logged out", "timestamp", Instant.now()));
            }
            
            // Revoke all refresh tokens for this user
            refreshTokenService.revokeTokensForUser(username);
            
            //
            // - once request is complete (/api/user/tasks, /api/admin/dashboard) spring clears the context automatically. Below line is not needed)
            // - we used logout method to clear entries in Redis
            // 
            // - But, in Spring Security, the SecurityContext always contains an Authentication object, even if nobody has logged in yet
            // - If no authentication is set, Spring creates an anonymous authentication:
            //   -- The principal is 'anonymousUser', Authorities are usually 'ROLE_ANONYMOUS'
            //            
            SecurityContextHolder.clearContext();SecurityContextHolder.getContext();

            return ResponseEntity.ok(Map.of(
                    "message", "Logged out successfully",
                    "timestamp", Instant.now()
            ));
        }

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("message", "No token provided", "timestamp", Instant.now()));
        */
    }
}


/*
Immediate Logout: The access token is deleted from Redis, so further requests fail immediately.
Refresh Token Handling: Stored in DB via RefreshTokenService and revoked on refresh or logout.
Redis TTL: Access tokens automatically expire in Redis according to JWT expiry.
Simple Map Responses: Includes timestamp for debugging/logging.
Exception Handling: Uses ResponseStatusException for 401 Unauthorized.
*/
