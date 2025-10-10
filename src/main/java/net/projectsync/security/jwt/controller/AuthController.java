package net.projectsync.security.jwt.controller;

import java.time.Instant;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.dto.ApiResponse;
import net.projectsync.security.jwt.dto.SignInRequest;
import net.projectsync.security.jwt.dto.SignupRequest;
import net.projectsync.security.jwt.dto.UserDTO;
import net.projectsync.security.jwt.entity.User;
import net.projectsync.security.jwt.mapper.UserMapper;
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

    private static final String COOKIE_PATH = "/api/auth"; // sends cookie to '/api/auth/signup', '/api/auth/signin', '/api/auth/refresh' and '/api/auth/logout'
    private static final long REFRESH_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 7; // 7 days
    
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<UserDTO>> signup(@RequestBody SignupRequest request) {

        // 1️. Check if username already exists
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists");
        }

        // 2️. Create new user
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(encoder.encode(request.getPassword())); 			// Secure password hashing
        try {
            user.setRole(Role.valueOf(request.getRole().toUpperCase())); 	// Ensure role is valid
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid role");
        }

        // 3️. Save user
        userRepository.save(user);

        // 4️. Convert user to userDto
        UserDTO dto = UserMapper.toDTO(user);
        ApiResponse<UserDTO> response = new ApiResponse<>("User registered successfully", Instant.now(), dto);
        
        // 5. Return success
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/signin")
    public ResponseEntity<ApiResponse<Map<String, Object>>> signin(@RequestBody SignInRequest request, HttpServletResponse response) {

        // 1️. Fetch user and verify credentials
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

        if (!encoder.matches(request.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        // 2️. Optional: prevent multiple logins per user
        if (refreshTokenService.hasActiveRefreshTokens(user.getUsername())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User already logged in");
        }

        // 3️. Generate JWT tokens
        String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String refreshToken = jwtService.generateRefreshToken(user.getUsername());

        // 4️. Store refresh token in Redis with TTL matching cookie
        refreshTokenService.saveRefreshToken(refreshToken, user.getUsername());

        // 5️. Set refresh token as HttpOnly, Secure, SameSite cookie
        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)                             // JS cannot access (mitigates XSS i.e, Cross Site Scripting))
                .secure(true)                               // Only sent over HTTPS
                // .path("/api/auth/refresh")               // Limit cookie to refresh endpoint
                .path("/api/auth")							// Cookie is sent automatically for '/api/auth/**' ==> ie. '/api/auth/signup', '/api/auth/signin', '/api/auth/refresh', '/api/auth/logout'
                											// ✅ '/signup' and '/signin' technically receive the cookie, but they don’t use it, and that’s 100% safe and standard.
                											// iff we have to restrict cookie only to '/refresh' and '/logout' then use path="/api/auth/refresh" and move logout endpoint under '/api/auth/refresh/logout'
                .maxAge(REFRESH_COOKIE_MAX_AGE_SECONDS)     // Cookie lifetime in seconds. (REFRESH_COOKIE_MAX_AGE_MS = REFRESH_COOKIE_MAX_AGE_SECONDS * 1000)
                .sameSite("Strict")                         // Restricts cross-site cookie sending. Provides CSRF protection. Adjust for cross-domain if needed
                											// CSRF is already disabled in SecurityConfig. But refresh token is technically a stateful cookie
                											// So, if you were worried about CSRF here, you might want CSRF just for that endpoint
                											// Using SameSite=Strict already mitigates most CSRF attacks because browsers won’t send the cookie in cross-site requests
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());    

        // 6. Convert user to userDto
        UserDTO dto = UserMapper.toDTO(user);
        Map<String, Object> data = Map.of(
                "accessToken", accessToken,
                "user", dto
        );

        // 7. Return access token in JSON. SPA should store in memory only (not localStorage or sessionStorage) to minimize XSS risk
        ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>("Signed in successfully", Instant.now(), data);
        return ResponseEntity.ok(apiResponse);
    }


    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<Map<String, Object>>> refresh(@CookieValue(name = "refreshToken", required = false) String oldRefreshToken,
    													HttpServletRequest request, 
    													HttpServletResponse response) {

    	/*
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
		*/
    	
        // 1️. Check if cookie exists
        if (oldRefreshToken == null || oldRefreshToken.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token missing");
        }

        // 2️. Validate refresh token signature and expiration
        if (!jwtService.isValidRefreshToken(oldRefreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
        }

        // 3️. Validate against Redis (or DB) to prevent reuse
        String username = refreshTokenService.getUsernameForRefreshToken(oldRefreshToken)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token not recognized"));

        // 4️. Revoke old refresh token for the user (in user set username:sachin as well as token123 -> sachin)
        refreshTokenService.revokeSingleRefreshToken(oldRefreshToken);

        // 5️. Generate new access token and refresh token
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        String newAccessToken = jwtService.generateAccessToken(username, user.getRole());
        String newRefreshToken = jwtService.generateRefreshToken(username);

        // 6️. Store new refresh token in Redis with expiry
        refreshTokenService.saveRefreshToken(newRefreshToken, username);

        // 7️. Set new refresh token in HttpOnly, Secure, SameSite cookie
        ResponseCookie cookie = ResponseCookie.from("refreshToken", newRefreshToken)
                .httpOnly(true)                             // JS cannot access (protects against XSS)
                .secure(true)                               // HTTPS only
                .path("/api/auth")    		                // Limit cookie to auth endpoint
                .maxAge(REFRESH_COOKIE_MAX_AGE_SECONDS)     // Lifetime in seconds
                .sameSite("Strict")                         // Protect against CSRF (use 'Lax' or 'None' if cross-domain). (HttpOnly + Secure + SameSite: All refresh cookies are protected)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        // 8. Convert user to userDto
        UserDTO dto = UserMapper.toDTO(user);
        Map<String, Object> data = Map.of(
                "accessToken", newAccessToken,
                "user", dto
        );

        // 8️. Return new access token (SPA stores it in memory only)
        ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>("Access token and Refresh token refreshed successfully", Instant.now(), data);
        return ResponseEntity.ok(apiResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@CookieValue(name="refreshToken", required = false) String refreshToken, HttpServletResponse response) {

        Instant now = Instant.now();

        // 1️. If no refresh token, user is effectively already logged out
        if (refreshToken == null || refreshToken.isBlank()) {
            ApiResponse<Void> apiResponse = new ApiResponse<>("User already logged out", now, null);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);
        }

        // 2️. Extract username from refresh token
        String username = jwtService.extractUsername(refreshToken);

        if (username == null || !refreshTokenService.hasActiveRefreshTokens(username)) {
            ApiResponse<Void> apiResponse = new ApiResponse<>("User already logged out", now, null);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);
        }

        // 3️. Revoke all refresh tokens for the user (in user set username:sachin as well as token123 -> sachin) during logout
        refreshTokenService.revokeAllRefreshTokensForUser(username);

        // 4️. Clear the refresh token cookie
        ResponseCookie clearedCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .path("/api/auth")	         // Limit to auth endpoint
                .maxAge(0)                   // Delete cookie
                .sameSite("Strict")          // CSRF protection. (HttpOnly + Secure + SameSite: All refresh cookies are protected)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, clearedCookie.toString());

        // 5️. Return logout confirmation
        ApiResponse<Void> apiResponse = new ApiResponse<>("Logged out successfully", now, null);
        return ResponseEntity.ok(apiResponse);        
        
        // Refer Note1: why 'SecurityContextHolder.clearContext()' is not needed in this scenario

        
        /* OLD CODE: Refresh token was being sent along with access token in response body which is incorrect approach
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


/* NOTE1
1. Purpose of SecurityContextHolder.clearContext():
	   - Clears the SecurityContext for the current thread.
	   - Removes the Authentication object (logged-in user info).

	2. In a stateless JWT setup:
	   - SessionCreationPolicy.STATELESS → no HTTP session is used.
	   - Authentication is derived from JWT on each request via JwtAuthFilter.
	   - Spring automatically clears the thread-local SecurityContext after the request ends.
	   - Therefore, calling clearContext() in logout is optional.

	3. When to use it:
	   - Only needed in stateful session-based setups.
	   - Useful if doing programmatic login/logout and want to clear thread-local immediately.

	4. Conclusion:
	   - In your stateless JWT + refresh token system, you can safely remove it.
	   - Logout will still:
	     a) Revoke refresh tokens in Redis.
	     b) Clear HttpOnly cookies.
	     c) Fail access with expired/invalid tokens on next request.

	5. Recommendation:
	   - Optional: keep for clarity, but not required.
*/
