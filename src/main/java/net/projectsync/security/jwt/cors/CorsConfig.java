package net.projectsync.security.jwt.cors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import java.util.List;

/**
 * CORS Configuration Guidelines:
 * - Use only CorsConfigurationSource → when all endpoints (public + protected) go through Spring Security.
 * - Use only WebMvcConfigurer → when your app doesn’t use Spring Security at all.
 * - Use both → only if you have a mix: some endpoints secured (via Spring Security) 
 * 				and others completely outside the security filter chain (e.g., static resources or /public/**).
 */
@Configuration
public class CorsConfig {


    /**
     * CorsConfigurationSource
     * - Used by Spring Security to handle CORS for endpoints that pass through the SecurityFilterChain.
     * - Use this when all your API endpoints are protected by Spring Security (e.g., /api/**).
     * - Sufficient for most backend APIs (like Spring Boot REST APIs called by React or Angular).
     * - Spring Security automatically handles CORS and preflight (OPTIONS) requests for secured endpoints.
     * - You do NOT need the inline cors() lambda in SecurityConfig if you have this bean
     */
	
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:3000"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));											// specifies whether headers are allowed
        config.setAllowCredentials(true);												// specifies whether credentials (cookies, auth headers) are allowed

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config); 								// applies to all endpoints
        return source;
    }
    
    /*
			// Alternate inline option (if you don’t define the CorsConfigurationSource bean)
			
			http
		        .cors(cors -> cors.configurationSource(request -> {
		            CorsConfiguration config = new CorsConfiguration();
		            config.setAllowedOrigins(List.of("http://localhost:3000"));						
		            config.setAllowedMethods(List.of("GET","POST","PUT","DELETE"));
		            config.setAllowCredentials(true);
		            config.setAllowedHeaders(List.of("*"));
		            return config;
		        }))
     */

    /* 
     * Note:
     * In SecurityConfig, we have added:
     *      	.antMatchers("/api/auth/**", "/actuator/**", "/management/**").permitAll()
     * 	- Even though /actuator/** and /management/** are public, they are still part of the Spring Security filter chain because we declared them in authorizeHttpRequests() with .permitAll()
     * 	- Spring Security still processes those requests — it just skips authentication. 
     * 	- Therefore, CORS is still handled by CorsConfigurationSource (not WebMvcConfigurer).
     *
     * Use WebMvcConfigurer only if:
     * 	- Your project has endpoints that completely bypass Spring Security, such as static resources or endpoints excluded from the filter chain (e.g., /public/**).
     * 	- Or if your project doesn’t use Spring Security at all.
     *
     * @CrossOrigin → Use only for very specific controller or method-level CORS.
     *
     * Preflight (OPTIONS) requests are automatically handled for secured routes.
     * See: OneNote
     * 	- Preflight Request: A preflight request is an automatic “check” the browser performs before sending a real cross-origin HTTP request, to ensure the server allows it.
     * 	- Preflight = browser asking the server “Can I make this cross-origin request?” before sending the actual request.
     */
    /*
    @Bean
    public WebMvcConfigurer mvcCorsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")												// Applies to all endpoints
                        .allowedOrigins("http://localhost:3000")						// Allows React frontend (or any app) running on port 3000. Ex: .allowedOrigins("https://your-production-domain.com")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")		// Allowed HTTP methods
                        .allowedHeaders("*")											// specifies whether headers are allowed
                        .allowCredentials(true);										// specifies whether credentials (cookies, auth headers) are allowed
            }
        };
    }
    */
}