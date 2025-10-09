package net.projectsync.security.jwt.configuration;

import java.util.List;

import javax.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.filter.JwtAuthFilter;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    	
    	http
    		// - When you build a stateless REST API using JWT, you don’t use sessions or cookies to track the user, so CSRF protection is unnecessary
    		// - Your JWT (Access/Refresh tokens) is sent in the Authorization: Bearer <token> header, so CSRF attacks don’t apply
    		// - Refresh token cookie → could be used to issue a new access token via /api/auth/refresh endpoint
    		// 		-- This is technically a stateful cookie, so if you were worried about CSRF here, you might want CSRF just for that endpoint.
    		// 		-- Using SameSite=Strict already mitigates most CSRF attacks because browsers won’t send the cookie in cross-site requests
	        .csrf(csrf -> csrf.disable())
	        // - If your frontend SPA is on a different domain/port, you should configure CORS here
	        // - Allows your frontend app (running at http://localhost:3000) to make requests to this backend.
	        // - You specify allowed methods, headers, and whether credentials (cookies, auth headers) are allowed
	        .cors(cors -> cors.configurationSource(request -> {
	            CorsConfiguration config = new CorsConfiguration();
	            config.setAllowedOrigins(List.of("http://localhost:3000"));						
	            config.setAllowedMethods(List.of("GET","POST","PUT","DELETE"));
	            config.setAllowCredentials(true);
	            config.setAllowedHeaders(List.of("*"));
	            return config;
	        }))
	        // The server will not create or use HTTP sessions. Every request must include the JWT token. This is standard for JWT-based authentication.
	        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
	        // - Adding a AuthenticationEntryPoint helps return consistent JSON error responses for unauthorized requests
	        // - Handles unauthenticated requests (when a user accesses a protected endpoint without a token).
	        // - Returns JSON instead of the default HTML login page.
	        // - Gives a consistent API error response
	        .exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, authEx) -> {
	            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	            res.setContentType("application/json");
	            res.getWriter().write("{\"error\":\"Unauthorized\"}");
	        }))	        
	        .authorizeHttpRequests(auth -> auth
	            .antMatchers("/api/auth/**").permitAll()			// public endpoints (login/register, etc.). No authentication is required to access these endpoints
	            .antMatchers("/api/admin/**").hasRole("ADMIN")		// only accessible by users with role ADMIN. JWT authentication needed
	            .antMatchers("/api/user/**").hasRole("USER")		// only accessible by users with role USER. JWT authentication needed
	            .anyRequest().authenticated()						// Any other endpoint → must be authenticated (using JWT)
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

