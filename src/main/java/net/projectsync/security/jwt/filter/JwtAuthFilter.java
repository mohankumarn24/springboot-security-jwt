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
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.projectsync.security.jwt.exception.InvalidJwtTokenException;
import net.projectsync.security.jwt.exception.JwtAuthenticationEntryPoint;
import net.projectsync.security.jwt.exception.UnauthorizedException;
import net.projectsync.security.jwt.model.Role;
import net.projectsync.security.jwt.repository.UserRepository;
import net.projectsync.security.jwt.service.JwtService;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        // 1️. Skip authentication for '/api/auth/**' endpoints (signup, signin, refresh, logout)
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
                // 3️. Extract claims once
                Claims claims = jwtService.extractAllClaims(token);
                String username = claims.getSubject();
                String tokenType = claims.get("type", String.class);

                if (username == null || tokenType == null) {
                    throw new InvalidJwtTokenException("JWT missing required claims");
                }
                
                // 4a. Only set SecurityContext for access tokens
                if ("access".equals(tokenType)) {
                	// Get role from claims
                	String roleName = claims.get("role", String.class);
                    if (roleName == null) {
                        throw new InvalidJwtTokenException("Access token missing role claim");
                    }

                    // 4b. Validate role presence
                    Role role;
                    try {
                        role = Role.valueOf(roleName);
                    } catch (IllegalArgumentException e) {
                        throw new InvalidJwtTokenException("Invalid role in access token", e);
                    }

                    // 4c. If username exists and SecurityContext is not yet set
                    if (SecurityContextHolder.getContext().getAuthentication() == null) {
                        UsernamePasswordAuthenticationToken authToken =
                                new UsernamePasswordAuthenticationToken(
                                        username,
                                        null,
                                        Collections.singletonList(new SimpleGrantedAuthority(role.asSpringRole()))
                                );
                        // 4d. Set authentication in Spring Security context
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            } 
            // 5️. Handle JWT related exceptions
            catch (UnauthorizedException e) {

                // Optional: log the JWT error
                log.warn("Unauthorized JWT access to {}: {}", request.getRequestURI(), e.getMessage());

                // ✅ These will NOT reach the GlobalExceptionHandler because you are writing to the response manually inside the filter
                //    Filters execute before controllers, so any exception thrown here must be handled manually or passed to an entry point.

                // Handle exception 1
                // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access token expired"); return;
                // ❌ This works, but sends a plain HTTP 401 with no JSON body. Not recommended if you want uniform JSON responses.

                // Handle exception 2
                // sendUnauthorized(response, "Access token expired"); return;
                // ✅ This works. You can manually write a JSON response. But it duplicates logic you already have in JwtAuthenticationEntryPoint.

                // Handle exception 3
                // throw new UnauthorizedException(e.getMessage());
                // ❌ This works only if you have a GlobalExceptionHandler for ApiException.  
                // ❌ But since you are inside a filter, this exception may not reach your handler reliably.

                // Handle exception 4
                // Delegate directly to the entry point
                jwtAuthenticationEntryPoint.commence(
                    request, 
                    response, 
                    new org.springframework.security.authentication.BadCredentialsException(e.getMessage(), e)
                );
                // ✅ Recommended approach. Uses your existing entry point to return uniform 401 JSON.
                return; // stop filter chain
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
    // same as JwtAuthenticationEntryPoint
    private void sendUnauthorized(HttpServletResponse response, String message) throws IOException {
    	
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        String body = String.format("{\"error\":\"%s\",\"timestamp\":\"%s\"}", message, Instant.now());
        response.getWriter().write(body);
    }
}