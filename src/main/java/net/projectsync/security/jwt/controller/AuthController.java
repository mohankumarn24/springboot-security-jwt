package net.projectsync.security.jwt.controller;

import java.time.Instant;
import java.util.Map;
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
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;

    @PostMapping("/signup")
    public ResponseEntity<Map<String, Object>> signup(@Valid @RequestBody SignupRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("message", "Username already exists", "timestamp", Instant.now()));
        }

        Role role;
        try {
            role = Role.valueOf(request.getRole().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid role");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(encoder.encode(request.getPassword()));
        user.setRole(role);
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "User registered successfully", "timestamp", Instant.now()));
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthResponse> signin(@Valid @RequestBody AuthRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username"));

        if (!encoder.matches(request.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid password");
        }

        String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String refreshToken = jwtService.generateRefreshToken(user.getUsername());

        refreshTokenService.saveToken(refreshToken, user.getUsername(),
                jwtService.extractAllClaims(refreshToken).getExpiration().toInstant());

        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        String oldToken = request.getRefreshToken();
        String username = jwtService.extractUsername(oldToken);

        if (username == null || !jwtService.isRefreshToken(oldToken) || !refreshTokenService.isValid(oldToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        refreshTokenService.revokeToken(oldToken);

        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String newRefreshToken = jwtService.generateRefreshToken(user.getUsername());

        refreshTokenService.saveToken(newRefreshToken, username,
                jwtService.extractAllClaims(newRefreshToken).getExpiration().toInstant());

        return ResponseEntity.ok(new AuthResponse(newAccessToken, newRefreshToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            String username = jwtService.extractUsername(token);

            refreshTokenService.revokeTokenForUser(username);
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
