package net.projectsync.security.jwt.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.exception.JwtAccessDeniedHandler;
import net.projectsync.security.jwt.exception.JwtAuthenticationEntryPoint;
import net.projectsync.security.jwt.filter.JwtAuthFilter;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    	
    	http
    		// - When you build a stateless REST API using JWT, you don’t use sessions or cookies to track the user, so CSRF protection is unnecessary
    		// - Your JWT (Access/Refresh tokens) is sent in the Authorization: Bearer <token> header, so CSRF attacks don’t apply
    		// - Refresh token cookie → could be used to issue a new access token via /api/auth/refresh endpoint
    		// 		-- This is technically a stateful cookie, so if you were worried about CSRF here, you might want CSRF just for that endpoint.
    		// 		-- Using SameSite=Strict already mitigates most CSRF attacks because browsers won’t send the cookie in cross-site requests
	        .csrf(csrf -> csrf.disable())	// need to enable if .sameSite("None") 
	        
	        // - If your frontend SPA is on a different domain/port, you should configure CORS here or use CorsConfig.java (use any one approach)
	        // - Allows your frontend app (running at http://localhost:3000) to make requests to this backend.
	        // - You specify allowed methods, headers, and whether credentials (cookies, auth headers) are allowed
	        .cors(Customizer.withDefaults())	// just enables CORS, Spring Security will automatically look for a CorsConfigurationSource bean which is added in 'CorsConfig.java'
	        
	        // The server will not create or use HTTP sessions. Every request must include the JWT token. This is standard for JWT-based authentication.
	        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
	        
	        // - Adding a AuthenticationEntryPoint helps return consistent JSON error responses for unauthorized requests
	        // - Handles unauthenticated requests (when a user accesses a protected endpoint without a token).
	        // - Returns JSON instead of the default HTML login page.
	        // - Gives a consistent API error response
	        /* Lambda approach
	        .exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, authEx) -> {
	            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	            res.setContentType("application/json");
	            res.getWriter().write("{\"error\":\"Unauthorized\"}");
	        }))
	        */
	        // Bean approach. See notes
	        .exceptionHandling(ex -> ex
	        	    .authenticationEntryPoint(jwtAuthenticationEntryPoint) 	// 401	Triggered when an unauthenticated user tries to access a protected resource.	(No token, Malformed/invalid token, Expired token, Token tampered / invalid signature)
	        	    .accessDeniedHandler(jwtAccessDeniedHandler)           	// 403	Triggered when an authenticated user tries to access a resource they don’t have permission for.	(Valid token, insufficient role)
	        	)															// GlobalExceptionHandler is for exceptions thrown inside controller methods.
	        																// AuthenticationEntryPoint / AccessDeniedHandler is for pre-controller, filter-chain security exceptions (401 / 403)
	        																// See: JWT Handling Checklist
	        .authorizeHttpRequests(auth -> auth
	            .antMatchers("/api/auth/**", "/actuator/**", "/management/**").permitAll()			
	            															// public endpoints (login/register, etc.). No authentication is required to access these endpoints
	            .antMatchers("/api/admin/**").hasRole("ADMIN")				// only accessible by users with role ADMIN. JWT authentication needed
	            .antMatchers("/api/user/**").hasRole("USER")				// only accessible by users with role USER. JWT authentication needed
	            .anyRequest().authenticated()								// Any other endpoint → must be authenticated (using JWT)
	            															// all endpoints including (/api/admin/**, /api/user/**) but not public endpints
	        )
	        
	        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);    	
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    /**
     * This bean prevents Spring Boot from creating a default in-memory user
     * and printing that "Using generated security password" log.
     */
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        return new InMemoryUserDetailsManager(); // empty, no default user
    }
}

/*
| Feature                                   | Bean Approach | Inline Lambda |
| ----------------------------------------- | ------------- | ------------- |
| Handles 401                               | ✅             | ✅             |
| Handles 403                               | ✅             | ❌ (defaults)  |
| Reusable                                  | ✅             | ❌             |
| Extensible (logging, token type messages) | ✅             | ❌             |
| Quick setup                               | ❌             | ✅             |
 */


/*
JWT Handling Checklist:

| Scenario                                        | Authenticated? | Handler                       | HTTP Status | Notes / Action                                                      |
| ----------------------------------------------- | -------------- | ----------------------------- | ----------- | ------------------------------------------------------------------- |
| **No token provided**                           | ❌              | `JwtAuthenticationEntryPoint` | 401         | User never sent `Authorization` header                              |
| **Empty token**                                 | ❌              | `JwtAuthenticationEntryPoint` | 401         | `Authorization: Bearer ` with nothing after `Bearer`                |
| **Malformed token**                             | ❌              | `JwtAuthenticationEntryPoint` | 401         | Token cannot be parsed (corrupted / wrong format)                   |
| **Invalid signature / tampered token**          | ❌              | `JwtAuthenticationEntryPoint` | 401         | Token signature does not match server secret                        |
| **Expired token**                               | ❌              | `JwtAuthenticationEntryPoint` | 401         | `exp` claim is past; optional custom message “Token expired”        |
| **Token revoked / blacklisted**                 | ❌              | `JwtAuthenticationEntryPoint` | 401         | Check in DB/Redis blacklist (especially for refresh tokens)         |
| **Token used in wrong endpoint**                | ❌              | `JwtAuthenticationEntryPoint` | 401         | Refresh token sent to resource endpoint or vice versa               |
| **Unsupported auth scheme**                     | ❌              | `JwtAuthenticationEntryPoint` | 401         | E.g., `Basic`, `Digest` instead of `Bearer`                         |
| **Token parsing exception**                     | ❌              | `JwtAuthenticationEntryPoint` | 401         | Catch `IllegalArgumentException`, `MalformedJwtException` in filter |
| **Valid token but insufficient role/authority** | ✅              | `JwtAccessDeniedHandler`      | 403         | User authenticated but lacks permission for endpoint                |
| **Valid token, authorized access**              | ✅              | N/A                           | 200/201     | Normal request flow; proceed to controller                          |
| **Repeated invalid attempts / throttling**      | ❌              | Optional custom handler       | 429         | Optional enhancement: track IP or user for rate limiting            |
*/
