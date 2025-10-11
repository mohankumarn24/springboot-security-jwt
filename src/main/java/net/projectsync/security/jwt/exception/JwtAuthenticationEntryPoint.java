package net.projectsync.security.jwt.exception;

import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.projectsync.security.jwt.util.ApiResponse;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    // Handles exception when you access protected endpoint (ex: /api/user/** or /api/admin/**) with empty Bearer token or a short malformed token (few random characters)
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        // Optional logging
        log.warn("Unauthorized access attempt to {}: {}", request.getRequestURI(), authException.getMessage());

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        ApiResponse<Void> apiResponse = new ApiResponse<>(
            authException.getMessage() + " (exception handled by JwtAuthenticationEntryPoint)",
            Instant.now(),
            null
        );

        // response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
        try (PrintWriter writer = response.getWriter()) {
            writer.write(objectMapper.writeValueAsString(apiResponse));
            writer.flush();
        }
    }
}
