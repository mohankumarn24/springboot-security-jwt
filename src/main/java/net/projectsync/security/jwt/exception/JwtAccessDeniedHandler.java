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
import net.projectsync.security.jwt.util.ApiResponse;

@Component
@RequiredArgsConstructor
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    // Displays message in responsebody when you dont have authorization to protected endpoint (ex: /api/user/** or /api/admin/**). Ex. Access '/api/admin/**' with 'USER' role
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        ApiResponse<Void> apiResponse = new ApiResponse<>(
        		accessDeniedException.getMessage() +  " (handled by JwtAccessDeniedHandler)",
            Instant.now(),
            null
        );

        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    }
}

