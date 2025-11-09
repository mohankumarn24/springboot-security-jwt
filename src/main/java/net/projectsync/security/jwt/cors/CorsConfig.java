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
	 * 1️. Spring Security CORS source (used in SecurityConfig.cors())
	 * 	- This handles secured endpoints (like /api/auth/** or JWT-protected APIs).
	 *	- You don’t need the inline cors() lambda in SecurityConfig if you have the bean CorsConfigurationSource
	 * 	- WebMvcConfigurer → handles everything else globally
	 *  - Used by Spring Security — applies to all routes that go through the SecurityFilterChain
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
     * 2️. Optional: global 'Spring MVC' CORS (for non-secured endpoints)
     * - Handles all endpoints outside of Spring Security, like Actuator endpoints (/actuator/**) or static resources.
     * - /actuator/** will now support CORS because of the WebMvcConfigurer.
     * - @CrossOrigin -> Only for specific controller/method
     * - Preflight requests (OPTIONS) are properly handled for secured routes
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
                registry.addMapping("/**")												// Applies to all endpoints
                        .allowedOrigins("http://localhost:3000")						// Allows React frontend (or any app) running on port 3000. Ex: .allowedOrigins("https://your-production-domain.com")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")		// Allowed HTTP methods
                        .allowedHeaders("*")											// specifies whether headers are allowed
                        .allowCredentials(true);										// specifies whether credentials (cookies, auth headers) are allowed
            }
        };
    }
}

/*
Comparison: WebMvcConfigurer vs CorsConfigurationSource
| Aspect                   | 'WebMvcConfigurer'                                    | 'CorsConfigurationSource'                          |
| ------------------------ | ----------------------------------------------------- | ---------------------------------------------------|
| **When to use**          | No Spring Security or simple CORS setup               | Recommended when using Spring Security             |
| **Applies to**           | Spring MVC layer only                                 | Spring Security + MVC                              |
| **Integration**          | Needs manual security config if using Spring Security | Automatically picked up by SecurityFilterChain     |
| **Modern best practice** | Legacy / simple setup                                 | ✅ Preferred for new apps (Spring Boot 2.7+ / 3.x) |



| Feature                      | `WebMvcConfigurer`             | `CorsConfigurationSource`    |
| ---------------------------- | ------------------------------ | ---------------------------- |
| Layer                        | Spring MVC                     | Spring Security              |
| When executed                | After security filters         | Before security filters      |
| Preflight (OPTIONS) handling | May fail if security blocks it | Always handled correctly     |
| Security integration         | Manual / separate              | Automatic                    |
| Recommended for              | Apps without Spring Security   | ✅ Apps with Spring Security  |
| Modern best practice         | Legacy/simple                  | ✅ Preferred for new projects |

What actually happens when both exist?
| Scenario                                 | What happens                                                         | Recommendation                                                    |
| ---------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------- |
| 🚫 **No Spring Security**                | Only `WebMvcConfigurer` runs → works fine                            | ✅ Use only 'WebMvcConfigurer'                                     |
| 🔐 **Spring Security present (default)** | 'CorsConfigurationSource' in SecurityFilterChain takes precedence    | ✅ Use only 'CorsConfigurationSource'                              |
| ⚔️ **Both defined**                      | Both beans exist, but the Security one wins for all protected routes | ⚠️ Confusing, avoid using both — you’ll get inconsistent behavior |

*/