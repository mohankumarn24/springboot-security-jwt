package net.projectsync.security.jwt.controller;

import java.util.Collections;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import net.projectsync.security.jwt.dto.AuthRequest;
import net.projectsync.security.jwt.dto.AuthResponse;
import net.projectsync.security.jwt.dto.RefreshRequest;
import net.projectsync.security.jwt.dto.SignupRequest;
import net.projectsync.security.jwt.entity.User;
import net.projectsync.security.jwt.repository.UserRepository;
import net.projectsync.security.jwt.service.JwtService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private PasswordEncoder encoder;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequest request) {
        
    	Optional<User> existingUser = userRepo.findByUsername(request.username);
        if (existingUser.isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }

        User user = new User();
        user.setUsername(request.username);
        user.setPassword(encoder.encode(request.password));
        user.setRole(request.role.toUpperCase());
        userRepo.save(user);

        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@RequestBody AuthRequest request) {
        
    	Optional<User> userOpt = userRepo.findByUsername(request.username);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username");
        }

        User user = userOpt.get();
        if (!encoder.matches(request.password, user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid password");
        }

        String accessToken = jwtService.generateToken(user.getUsername());
        String refreshToken = jwtService.generateRefreshToken(user.getUsername());
        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {
    	
        String username = jwtService.extractUsername(request.getRefreshToken());
        if (username == null || !jwtService.validateToken(request.getRefreshToken(), 
        		new org.springframework.security.core.userdetails.User(username, "", Collections.emptyList()))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }
        String newAccessToken = jwtService.generateToken(username);
        return ResponseEntity.ok(new AuthResponse(newAccessToken, request.getRefreshToken()));
    }
    
    @PostMapping("/logout")
    public ResponseEntity<String> logout() {
        
    	SecurityContextHolder.clearContext();
        return ResponseEntity.ok("Logged out successfully");
    }
}