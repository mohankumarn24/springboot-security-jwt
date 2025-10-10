package net.projectsync.security.jwt.exception;

import java.nio.file.AccessDeniedException;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import net.projectsync.security.jwt.util.ApiResponse;

// Global @ControllerAdvice handlers do NOT catch exceptions thrown in the Spring Security filter chain
// Controller-level exception handling (@ControllerAdvice) only applies to exceptions thrown inside controller methods or during controller request mapping.
// Spring Security filters (like your JwtAuthFilter) run before the request reaches the controller.
// If an exception occurs in the filter chain (e.g., invalid JWT, missing token), it never enters the controller. Instead, Spring Security internally triggers either:
// 	- AuthenticationEntryPoint → for 401 Unauthorized (unauthenticated access)
//  - AccessDeniedHandler → for 403 Forbidden (authenticated but insufficient privileges)
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiResponse<Void>> handleApiException(ApiException ex) {
        ApiResponse<Void> response = new ApiResponse<>(ex.getMessage(), Instant.now(), null);
        return ResponseEntity.status(ex.getStatus().value()).body(response);
    }

    // AccessDeniedException does not extend Exception in a way that Spring will route it here for @ControllerAdvice by default in security filters.
    // By the time Spring Security throws it, it happens before the controller method is entered, inside the security filter chain. That means the exception does not go through the controller's normal exception handling. So, handle explicitly
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccessDenied(AccessDeniedException ex) {
        ApiResponse<Void> response = new ApiResponse<>(
            "You are not authorized to access this resource (Handled by Global Exception Handler)",
            Instant.now(),
            null
        );
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleException(Exception ex) {
        ApiResponse<Void> response = new ApiResponse<>("Internal server error (Handled by Global Exception Handler)", Instant.now(), null);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
    
    /**
     * Note:
     * 	If you also want to handle unauthenticated users (401 Unauthorized) when JWT is missing or invalid,
     *  you should handle AuthenticationException in a custom AuthenticationEntryPoint because Spring Security handles it at the filter level, not through @ControllerAdvice.
     */
}