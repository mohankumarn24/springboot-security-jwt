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
    		// Disable CSRF for stateless JWT APIs
	        .csrf(csrf -> csrf.disable())
	        // If your frontend SPA is on a different domain/port, you should configure CORS here
	        .cors(cors -> cors.configurationSource(request -> {
	            CorsConfiguration config = new CorsConfiguration();
	            config.setAllowedOrigins(List.of("http://localhost:3000"));
	            config.setAllowedMethods(List.of("GET","POST","PUT","DELETE"));
	            config.setAllowCredentials(true);
	            config.setAllowedHeaders(List.of("*"));
	            return config;
	        }))
	        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
	        // Adding a AuthenticationEntryPoint helps return consistent JSON error responses for unauthorized requests
	        .exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, authEx) -> {
	            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	            res.setContentType("application/json");
	            res.getWriter().write("{\"error\":\"Unauthorized\"}");
	        }))	        
	        .authorizeHttpRequests(auth -> auth
	            .antMatchers("/api/auth/**").permitAll()
	            .antMatchers("/api/admin/**").hasRole("ADMIN")
	            .antMatchers("/api/user/**").hasRole("USER")
	            .anyRequest().authenticated()
	        )
	        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);    	
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

