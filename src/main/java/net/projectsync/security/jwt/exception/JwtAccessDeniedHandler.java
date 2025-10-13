package net.projectsync.security.jwt.exception;

import java.io.IOException;
import java.io.PrintWriter;
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
 *  AccessDeniedException does not extend Exception in a way that Spring will route it here for @ControllerAdvice by default in security filters.
 *  By the time Spring Security throws it, it happens before the controller method is entered, inside the security filter chain. 
 *  That means the exception does not go through the controller's normal exception handling. So, handle explicitly
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    // Displays message in responsebody when you dont have authorization to protected endpoint (ex: /api/user/** or /api/admin/**). Ex. Access '/api/admin/**' with 'USER' role
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {

        // Optional logging
        log.warn("Access denied to {} by user {}: {}", request.getRequestURI(), request.getUserPrincipal(), accessDeniedException.getMessage());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");					// Otherwise some clients might misinterpret non-ASCII characters.
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        ApiResponse<Void> apiResponse = new ApiResponse<>("AccessDeniedHandler: " + accessDeniedException.getMessage(), Instant.now(), null);

        // response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
        try (PrintWriter writer = response.getWriter()) {					// Returns a PrintWriter to write character data to the HTTP response body. You can only call getWriter() once per response.
            writer.write(objectMapper.writeValueAsString(apiResponse));		// Writes the JSON string to the response body. Combined with setting the content type, the client receives JSON.
            writer.flush();
        }
    }
}

