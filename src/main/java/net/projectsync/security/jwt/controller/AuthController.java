package net.projectsync.security.jwt.controller;

import java.time.Instant;
import java.util.UUID;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.dto.SignInRequest;
import net.projectsync.security.jwt.dto.SignupRequest;
import net.projectsync.security.jwt.dto.TokenResponse;
import net.projectsync.security.jwt.dto.UserDTO;
import net.projectsync.security.jwt.entity.User;
import net.projectsync.security.jwt.exception.BadRequestException;
import net.projectsync.security.jwt.exception.ConflictException;
import net.projectsync.security.jwt.exception.ForbiddenException;
import net.projectsync.security.jwt.exception.UnauthorizedException;
import net.projectsync.security.jwt.mapper.UserMapper;
import net.projectsync.security.jwt.model.Role;
import net.projectsync.security.jwt.repository.UserRepository;
import net.projectsync.security.jwt.service.JwtService;
import net.projectsync.security.jwt.service.RefreshTokenService;
import net.projectsync.security.jwt.util.ApiResponse;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;

    private static final String REFRESH_COOKIE_NAME = "refreshToken";				// cookie name
    private static final String COOKIE_PATH = "/api/auth"; 							// sends cookie to '/api/auth/signup', '/api/auth/signin', '/api/auth/refresh' and '/api/auth/logout'
    private static final long REFRESH_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 7; 	// 7 days
    
    private static final String CSRF_COOKIE_NAME = "XSRF-TOKEN";
    
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<UserDTO>> signup(@RequestBody SignupRequest request) {

        // 1️. Check if username already exists
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new ConflictException("Username already exists");
        }

        // 2️. Create new user
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(encoder.encode(request.getPassword()));
        try {
            user.setRole(Role.valueOf(request.getRole().toUpperCase()));
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Invalid role");
        }
        
        // 3️. Save user
        userRepository.save(user);

        // 4️. Return API response
        ApiResponse<UserDTO> apiResponse = new ApiResponse<>("User registered successfully", Instant.now(),  UserMapper.toDTO(user));
        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);
    }

    
    @PostMapping("/signin")
    public ResponseEntity<ApiResponse<TokenResponse>> signin(@RequestBody SignInRequest request, HttpServletResponse response) {

        // 1️. Fetch user and verify credentials
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));

        if (!encoder.matches(request.getPassword(), user.getPassword())) {
            throw new UnauthorizedException("Invalid credentials");
        }

        // 2️. Optional: prevent multiple logins per user
        if (refreshTokenService.hasActiveRefreshTokens(user.getUsername())) {
            throw new ForbiddenException("User already logged in");
        }

        // 3️. Generate JWT tokens
        String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String refreshToken = jwtService.generateRefreshToken(user.getUsername());

        // 4️. Store refresh token in Redis with TTL matching cookie
        refreshTokenService.saveRefreshToken(refreshToken, user.getUsername());

        // 5️. Set refresh token as HttpOnly, Secure, SameSite cookie
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE_NAME, refreshToken)	// cookie name & cookie value
                .httpOnly(true)                             // JS cannot access (mitigates XSS i.e, Cross Site Scripting))
                .secure(true)                               // Only sent over HTTPS
                // .path("/api/auth/refresh")               // Limit cookie to refresh endpoint
                .path(COOKIE_PATH)							// Cookie is sent automatically for '/api/auth/**' ==> ie. '/api/auth/signup', '/api/auth/signin', '/api/auth/refresh', '/api/auth/logout'
                											// ✅ '/signup' and '/signin' technically receive the cookie, but they don’t use it, and that’s 100% safe and standard.
                											// iff we have to restrict cookie only to '/refresh' and '/logout' then use path="/api/auth/refresh" and move logout endpoint under '/api/auth/refresh/logout'
                .maxAge(REFRESH_COOKIE_MAX_AGE_SECONDS)     // Cookie lifetime in seconds. (REFRESH_COOKIE_MAX_AGE_MS = REFRESH_COOKIE_MAX_AGE_SECONDS * 1000)
                .sameSite("Strict")                         // Restricts cross-site cookie sending. Provides CSRF protection. Adjust for cross-domain if needed
                											// CSRF is already disabled in SecurityConfig. But refresh token is technically a stateful cookie
                											// So, if you were worried about CSRF here, you might want CSRF just for that endpoint
                											// Using SameSite=Strict already mitigates most CSRF attacks because browsers won’t send the cookie in cross-site requests
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());    
        													// If a cookie named "refreshToken" already exists with the same path and domain, the browser/Postman automatically replaces it.
        													// Old cookie is deleted and replaced; you do not need manual deletion.

        // 6. Generate CSRF token (random) and set CSRF cookie (non-HttpOnly, readable by JS)
        String csrfToken = UUID.randomUUID().toString();
        ResponseCookie csrfCookie = ResponseCookie.from(CSRF_COOKIE_NAME, csrfToken)
                .httpOnly(false)
                .secure(true)
                .sameSite("None")
                .path("/")
                .maxAge(REFRESH_COOKIE_MAX_AGE_SECONDS)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, csrfCookie.toString());
        
        // 7. Return access token in JSON. SPA should store in memory only (not localStorage or sessionStorage) to minimize XSS risk
        TokenResponse tokenResponse = new TokenResponse(accessToken, UserMapper.toDTO(user));
        ApiResponse<TokenResponse> apiResponse = new ApiResponse<>("Signed in successfully", Instant.now(), tokenResponse);
        return ResponseEntity.ok(apiResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<TokenResponse>> refresh(
										    		@CookieValue(name = REFRESH_COOKIE_NAME, required = false) String oldRefreshToken,
										    		@CookieValue(name = CSRF_COOKIE_NAME, required = false) String csrfCookieValue,
										    		@RequestHeader(value = "X-XSRF-TOKEN", required = false) String csrfHeaderValue,
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
            throw new UnauthorizedException("Refresh token missing");
        }

        // 2. CSRF double-submit validation
        if (csrfCookieValue == null || csrfHeaderValue == null || !csrfCookieValue.equals(csrfHeaderValue)) {
            throw new ForbiddenException("CSRF token mismatch");
        }
        
        // 3. Validate and rotate refresh token
        if (!jwtService.isValidRefreshToken(oldRefreshToken)) {
            throw new UnauthorizedException("Invalid or expired refresh token");
        }

        // 4️. Validate against Redis (or DB) to prevent reuse
        String username = refreshTokenService.getUsernameForRefreshToken(oldRefreshToken)
                .orElseThrow(() -> new UnauthorizedException("Unrecognized refresh token"));

        // 5. Revoke old refresh token for the user (in user set username:sachin as well as token123 -> sachin)
        refreshTokenService.revokeSingleRefreshToken(oldRefreshToken);

        // 6. Generate new access token and refresh token
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UnauthorizedException("User not found"));

        String newAccessToken = jwtService.generateAccessToken(username, user.getRole());
        String newRefreshToken = jwtService.generateRefreshToken(username);

        // 7. Store new refresh token in Redis with expiry
        refreshTokenService.saveRefreshToken(newRefreshToken, username);

        // 8️. Set new refresh token in HttpOnly, Secure, SameSite cookie
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE_NAME, newRefreshToken)	// cookie name & cookie value
                .httpOnly(true)                             // JS cannot access (protects against XSS)
                .secure(true)                               // HTTPS only
                .path(COOKIE_PATH)    		                // Limit cookie to auth endpoint. (If path is different old cookie will not be replaced and new cookie will be created)
                .maxAge(REFRESH_COOKIE_MAX_AGE_SECONDS)     // Lifetime in seconds
                .sameSite("Strict")                         // Protect against CSRF (use 'Lax' or 'None' if cross-domain). (HttpOnly + Secure + SameSite: All refresh cookies are protected)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        													// You revoke the old token in Redis.
        													// You generate a new refresh token and send it in the same cookie name + path.
        													// Browser/Postman automatically replaces the old cookie with the new one.

        // 8️. Return new access token (SPA stores it in memory only)
        TokenResponse tokenResponse = new TokenResponse(newAccessToken, UserMapper.toDTO(user));
        ApiResponse<TokenResponse> apiResponse = new ApiResponse<>("Tokens refreshed successfully", Instant.now(), tokenResponse);
        return ResponseEntity.ok(apiResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            							@CookieValue(name = REFRESH_COOKIE_NAME, required = false) String refreshToken,
            							@CookieValue(name = CSRF_COOKIE_NAME, required = false) String csrfCookieValue,
            							@RequestHeader(value = "X-XSRF-TOKEN", required = false) String csrfHeaderValue,
            							HttpServletResponse response) {

        // 1️. If no refresh token, user is effectively already logged out
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new BadRequestException("User already logged out or no refresh token provided");
        }

        // 2️. Double Submit CSRF protection
        if (csrfCookieValue == null || csrfHeaderValue == null || !csrfCookieValue.equals(csrfHeaderValue)) {
            throw new ForbiddenException("CSRF token mismatch");
        }
        
        // 3. Validate refresh token and user
        String username = jwtService.extractUsername(refreshToken);
        if (username == null || !refreshTokenService.hasActiveRefreshTokens(username)) {
            throw new BadRequestException("User already logged out");
        }

        // 4️. Revoke all refresh tokens for the user (in user set username:sachin as well as token123 -> sachin) during logout
        refreshTokenService.revokeAllRefreshTokensForUser(username);

        // 5️. Clear the 'refreshToken' cookie
        ResponseCookie clearedCookie = ResponseCookie.from(REFRESH_COOKIE_NAME, "")	// cookie name & cookie value
                .httpOnly(true)
                .secure(true)
                .path(COOKIE_PATH)	         // Limit to auth endpoint. If path is different cookie will not be removed
                .maxAge(0)                   // Delete cookie
                .sameSite("Strict")          // CSRF protection. (HttpOnly + Secure + SameSite: All refresh cookies are protected)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, clearedCookie.toString());
        									// ✅ If the path matches the existing cookie, it is removed from the browser/Postman.
        									// ❌ If path differs, the cookie is not cleared, and you may see an old cookie remain.
        
        // 6️. Clear the 'XSRF-TOKEN' cookie
        ResponseCookie clearCsrf = ResponseCookie.from(CSRF_COOKIE_NAME, "")
                .httpOnly(false)
                .secure(true)
                .path("/")
                .sameSite("None")
                .maxAge(0)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, clearCsrf.toString());
        
        // 7. Return logout confirmation
        ApiResponse<Void> apiResponse = new ApiResponse<>("Logged out successfully", Instant.now(), null);
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

/*  
	Cookie Path
	-----------
	
	A. Key Takeaways:
		| Endpoint   | Cookie Behavior                                          |
		| ---------- | -------------------------------------------------------- |
		| `/signin`  | Replaces old cookie automatically                        |
		| `/refresh` | Replaces old cookie automatically                        |
		| `/logout`  | Clears cookie if path matches exactly                    |
		| `/signup`  | Receives cookie in request headers but ignores it (safe) |
	
	
	B. Common Mistakes That Cause “Old Cookie Not Cleared”:
		1. Path mismatch:
			- /signin sets cookie at /api/auth
			- /logout clears cookie at /api/auth/refresh → old cookie remains.
		2. Multiple cookies with same name but different paths:
			- Browser/Postman shows both cookies; clearing one doesn’t affect the other.
		3. Postman caching: 
			- Postman may display old cookies even after a replacement — use the cookie manager to verify.
	
	C. Recommendation:
		1. Use the same cookie path for all refresh token operations (/api/auth)
		2. Keep the cookie name consistent (refreshToken)
		3. Ensure /logout uses exact same path as used in /signin and /refresh.
*/