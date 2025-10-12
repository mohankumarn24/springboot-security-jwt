package net.projectsync.security.jwt.cors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import java.util.List;

@Configuration
public class CorsConfig {

	/**
	 * 1️. Spring ***Security CORS*** source (used in SecurityConfig.cors())
	 * 	- This handles secured endpoints (like /api/auth/** or JWT-protected APIs).
	 *	- You don’t need the inline cors() lambda in SecurityConfig if you have the bean — your approach is cleaner.
	 * 	- WebMvcConfigurer → handles everything else globally
	 */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:3000"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));			// specifies whether headers are allowed
        config.setAllowCredentials(true);				// specifies whether credentials (cookies, auth headers) are allowed

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config); // applies to all endpoints
        return source;
    }
    
    /*
			// If you don't need above CorsConfigurationSource bean, then you simply add below lines in SecurityConfig() and remove above method. Use any one approach
			
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

    // 
    /**
     * 2️. Optional: global ***Spring MVC*** CORS (for non-secured endpoints)
     * - Handles all endpoints outside of Spring Security, like Actuator endpoints (/actuator/**) or static resources.
     * - /actuator/** will now support CORS because of the WebMvcConfigurer.
     * - @CrossOrigin -> Only for specific controller/method
     * 
     * - See: OneNote
     * - Preflight Request: A preflight request is an automatic “check” the browser performs before sending a real cross-origin HTTP request, to ensure the server allows it.
     * - Preflight = browser asking the server “Can I make this cross-origin request?” before sending the actual request.
     * @return
     */
    @Bean
    public WebMvcConfigurer mvcCorsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:3000")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*")			// specifies whether headers are allowed
                        .allowCredentials(true);		// specifies whether credentials (cookies, auth headers) are allowed
            }
        };
    }
}