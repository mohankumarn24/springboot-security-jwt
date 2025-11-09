package net.projectsync.security.jwt.exception;

import java.io.IOException;
import java.time.Instant;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.projectsync.security.jwt.util.ApiResponse;

/*
 * AccessDeniedException occurs within Spring Security's filter chain, before the request reaches any @RestController method.
 * Because of this, it is not handled by @RestControllerAdvice exception handlers (which only catch exceptions thrown inside controller methods).
 * Therefore, AccessDeniedException must be handled explicitly. For example, using a custom AccessDeniedHandler in Spring Security configuration.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;
    
    // Handles requests where the authenticated user lacks authorization to access a protected endpoint (e.g., accessing `/api/admin/**` with `ROLE_USER`).
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {

        log.warn("Access denied for URI [{}], user [{}]: {}", 
        		request.getRequestURI(), 
        		request.getUserPrincipal(), 
        		accessDeniedException.getMessage());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");					// Otherwise some clients might misinterpret non-ASCII characters. Ensures correct encoding for non-ASCII characters
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        ApiResponse<Void> apiResponse = new ApiResponse<>(
        		"AccessDeniedHandler: " + accessDeniedException.getMessage(),
        		Instant.now(), 
        		null);
        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    }
}
