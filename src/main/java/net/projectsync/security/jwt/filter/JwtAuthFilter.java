package net.projectsync.security.jwt.filter;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.exception.UnauthorizedException;
import net.projectsync.security.jwt.model.Role;
import net.projectsync.security.jwt.repository.UserRepository;
import net.projectsync.security.jwt.service.JwtService;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        // 1️. Skip authentication for /api/auth endpoints (login, signup, refresh, logout)
        String path = request.getServletPath();
        if (path.startsWith("/api/auth/")) {
            chain.doFilter(request, response);
            return;
        }

        // 2️. Extract Bearer token from Authorization header
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // remove "Bearer " prefix

            try {
                // 3️. Extract username from JWT
                String username = jwtService.extractUsername(token);

                // 4️. If username exists and SecurityContext is not yet set
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                    // 4a️. Extract role directly from JWT claims
                    String roleName = jwtService.extractAllClaims(token).get("role", String.class);

                    // 4b️. Validate role presence
                    if (roleName == null) {
                    	// response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Role not found in token");  --> dont use this
                    	throw new UnauthorizedException("Role not found in token");
                    }

                    // 4c️. Convert role string to Role enum
                    Role role;
                    try {
                        role = Role.valueOf(roleName);
                    } catch (IllegalArgumentException e) {
                    	// // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid role in token");  --> dont use this
                    	throw new UnauthorizedException("Invalid role in token");
                    }

                    // 4d️. Set authentication in Spring Security context
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    username,
                                    null,
                                    Collections.singletonList(new SimpleGrantedAuthority(role.asSpringRole()))
                            );
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                	
                    /*
                    User user = userRepository.findByUsername(username).orElse(null); // hits db, impacts performance. Refer Note1
                    if (user != null) {
                        String role = user.getRole().asSpringRole();	// we can get this from token itself, if we have added it in claims
                        UsernamePasswordAuthenticationToken authToken =
                                new UsernamePasswordAuthenticationToken(username, 
                                null,
                                Collections.singletonList(new SimpleGrantedAuthority(role)));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                    */                      
                }
            } 
            // 5️. Handle expired JWT
            catch (ExpiredJwtException e) {
            	// These will NOT reach the GlobalExceptionHandler because you are writing to the response manually inside the filter
                // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access token expired"); return;
            	// sendUnauthorized(response, "Access token expired"); return;
                throw new UnauthorizedException("Access token expired");
            } 
            // 6️. Handle invalid JWT
            catch (JwtException e) {
                // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token"); return;
                throw new UnauthorizedException("Invalid token");
            }
        }

        // 7️. Continue filter chain
        chain.doFilter(request, response);
    }
    
    /**
     * when an access token is expired, the response is a structured JSON with an explicit code/message. 
     * This makes it much easier for the frontend to detect an expired token and trigger a refresh.
	 *
     * Structured JSON 401 response
     * {
     *	 "error": "Access token expired",
     *   "timestamp": "2025-10-03T12:34:56Z"
	 * }
	 * 
	 * Frontend can now detect "Access token expired" and call /refresh automatically
	 * 
	 * Frontend Usage:
     * try {
     *     const data = await fetch("/api/user/tasks", { 
     *         headers: { Authorization: `Bearer ${accessToken}` } 
     *     });
     *     if (data.error === "Access token expired") {
     *         // call /refresh, update accessToken, retry
     *     }
     * } catch (err) {
     *     console.error(err);
     * }
     */
    private void sendUnauthorized(HttpServletResponse response, String message) throws IOException {
    	
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        String body = String.format("{\"error\":\"%s\",\"timestamp\":\"%s\"}", message, Instant.now());
        response.getWriter().write(body);
    }
}

/*

	1. Why you no longer need response.sendError()?
	 - Filters are early in the request chain, and normally you write directly to the response.
	 - But throwing an exception instead allows centralized handling, ensures consistent JSON responses, and avoids duplicated code.


	2. What happens on expired/invalid tokens?
	ExpiredJwtException → throws UnauthorizedException("Access token expired").
	JwtException → throws UnauthorizedException("Invalid token").
	Both are caught by GlobalExceptionHandler → client receives a JSON response like:
	
	{
	  "message": "Access token expired",
	  "timestamp": "2025-10-10T15:00:00Z",
	  "data": null
	}

*/


/*
	3. REMOVED in securityConfig:
	// - Adding a AuthenticationEntryPoint helps return consistent JSON error responses for unauthorized requests
	// - Handles unauthenticated requests (when a user accesses a protected endpoint without a token).
	// - Returns JSON instead of the default HTML login page.
	// - Gives a consistent API error response
	.exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, authEx) -> {
	    res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	    res.setContentType("application/json");
	    res.getWriter().write("{\"error\":\"Unauthorized\"}");
	}))


	4. ADDED in securityConfig:
	.exceptionHandling(ex -> ex.authenticationEntryPoint(jwtAuthenticationEntryPoint))
*/