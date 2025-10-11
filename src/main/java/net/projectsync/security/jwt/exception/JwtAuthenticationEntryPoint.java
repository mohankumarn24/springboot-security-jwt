package net.projectsync.security.jwt.exception;

import java.io.IOException;
import java.time.Instant;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.util.ApiResponse;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    // Handles exception when you access protected endpoint (ex: /api/user/** or /api/admin/**) with empty Bearer token or a short malformed token (few random characters)
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        ApiResponse<Void> apiResponse = new ApiResponse<>(
            authException.getMessage() + " (exception handled by JwtAuthenticationEntryPoint)",
            Instant.now(),
            null
        );

        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    }
}
