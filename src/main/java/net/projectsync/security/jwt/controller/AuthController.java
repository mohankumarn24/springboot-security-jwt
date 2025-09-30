package net.projectsync.security.jwt.controller;

import java.time.Instant;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
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
import net.projectsync.security.jwt.service.RefreshTokenService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	@Autowired
	private JwtService jwtService;

	@Autowired
	private RefreshTokenService refreshTokenService;

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private PasswordEncoder encoder;

	@PostMapping("/signup")
	public ResponseEntity<String> signup(@RequestBody SignupRequest request) {
		if (userRepository.findByUsername(request.username).isPresent()) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
		}

		User user = new User();
		user.setUsername(request.username);
		user.setPassword(encoder.encode(request.password));
		user.setRole(request.role.toUpperCase());
		userRepository.save(user);

		return ResponseEntity.ok("User registered successfully");
	}

	@PostMapping("/signin")
	public ResponseEntity<?> signin(@RequestBody AuthRequest request) {
		Optional<User> userOpt = userRepository.findByUsername(request.username);
		if (userOpt.isEmpty()) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username");
		}

		User user = userOpt.get();
		if (!encoder.matches(request.password, user.getPassword())) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid password");
		}

		String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
		String refreshToken = jwtService.generateRefreshToken(user.getUsername());

		// save refresh token in db
		Instant expiry = jwtService.extractAllClaims(refreshToken).getExpiration().toInstant();
		refreshTokenService.saveToken(refreshToken, user.getUsername(), expiry);

		return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
	}

	@PostMapping("/refresh")
	public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {
		String token = request.getRefreshToken();
		String username = jwtService.extractUsername(token);

		if (username == null || !jwtService.isRefreshToken(token) || !refreshTokenService.isValid(token)) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired refresh token");
		}

		Optional<User> userOpt = userRepository.findByUsername(username);
		if (userOpt.isEmpty()) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found");
		}

		// Revoke old token
		refreshTokenService.revokeToken(token);

		// Issue new tokens
		User user = userOpt.get();
		String newAccessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
		String newRefreshToken = jwtService.generateRefreshToken(user.getUsername());

		// Save new refresh token
		Instant expiry = jwtService.extractAllClaims(newRefreshToken).getExpiration().toInstant();
		refreshTokenService.saveToken(newRefreshToken, username, expiry);

		return ResponseEntity.ok(new AuthResponse(newAccessToken, newRefreshToken));
	}

	@PostMapping("/logout")
	public ResponseEntity<String> logout(HttpServletRequest request) {
		String authHeader = request.getHeader("Authorization");
		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			String token = authHeader.substring(7);
			String username = jwtService.extractUsername(token);

			refreshTokenService.revokeTokenForUser(username);
			SecurityContextHolder.clearContext();
			return ResponseEntity.ok("Logged out successfully");
		}
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("No token provided");
	}
}