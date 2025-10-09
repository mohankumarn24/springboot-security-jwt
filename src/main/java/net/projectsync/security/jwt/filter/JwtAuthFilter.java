package net.projectsync.security.jwt.filter;

import java.io.IOException;
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
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Role not found in token");
                        return;
                    }

                    // 4c️. Convert role string to Role enum
                    Role role;
                    try {
                        role = Role.valueOf(roleName);
                    } catch (IllegalArgumentException e) {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid role in token");
                        return;
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
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access token expired");
                return;
            } 
            // 6️. Handle invalid JWT
            catch (JwtException e) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
                return;
            }
        }

        // 7️. Continue filter chain
        chain.doFilter(request, response);
    }
}
