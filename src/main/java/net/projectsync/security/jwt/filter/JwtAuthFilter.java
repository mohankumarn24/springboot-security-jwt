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
import net.projectsync.security.jwt.entity.User;
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

        String path = request.getServletPath();
        if (path.startsWith("/api/auth/")) {
            chain.doFilter(request, response); // skip auth endpoints
            return;
        }

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                String username = jwtService.extractUsername(token);
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    // Extract role directly from JWT. Now authentication is purely from token claims → fully stateless
                    String role = jwtService.extractAllClaims(token).get("role", String.class);
                    if (role == null) {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Role not found in token");
                        return;
                    }   
                    
                    // Create authentication token and set in context
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    username,
                                    null,
                                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role)) // TODO: remove hardcoding
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
            } catch (ExpiredJwtException e) {
                sendUnauthorized(response, "Access token expired");
                return;                
            } catch (JwtException e) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
                return;
            }
        }

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


