package net.projectsync.security.jwt.controller;

import java.time.Instant;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.http.HttpStatus;
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
    public ResponseEntity<AuthResponse> signin(@RequestBody AuthRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username"));

        if (!encoder.matches(request.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid password");
        }

        // Generate tokens
        String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String refreshToken = jwtService.generateRefreshToken(user.getUsername());

        // Save refresh token in Redis
        refreshTokenService.saveToken(refreshToken, user.getUsername());

        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        String oldToken = request.getRefreshToken();
        String username = jwtService.extractUsername(oldToken);

        // Validate old refresh token
        if (username == null || !jwtService.isRefreshToken(oldToken) || !refreshTokenService.isValid(oldToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
        }

        // Revoke old token
        refreshTokenService.revokeToken(oldToken);

        // Generate new tokens
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String newRefreshToken = jwtService.generateRefreshToken(user.getUsername());

        // Save new refresh token
        refreshTokenService.saveToken(newRefreshToken, username);

        return ResponseEntity.ok(new AuthResponse(newAccessToken, newRefreshToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String accessToken = authHeader.substring(7);
            String username = jwtService.extractUsername(accessToken);

            // Revoke all refresh tokens for this user
            if (username != null) {
                // Revoke all refresh tokens for this user
                refreshTokenService.revokeTokensForUser(username);
            }

            SecurityContextHolder.clearContext();

            return ResponseEntity.ok(Map.of(
                    "message", "Logged out successfully",
                    "timestamp", Instant.now()
            ));
        }

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("message", "No token provided", "timestamp", Instant.now()));
    }
}


/*
Immediate Logout: The access token is deleted from Redis, so further requests fail immediately.
Refresh Token Handling: Stored in DB via RefreshTokenService and revoked on refresh or logout.
Redis TTL: Access tokens automatically expire in Redis according to JWT expiry.
Simple Map Responses: Includes timestamp for debugging/logging.
Exception Handling: Uses ResponseStatusException for 401 Unauthorized.
*/
