package net.projectsync.security.jwt.exception;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import javax.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.NoHandlerFoundException;
import net.projectsync.security.jwt.util.ApiResponse;

// Global @ControllerAdvice handlers do NOT catch exceptions thrown in the Spring Security filter chain. Ex: 401 Unauthorized, 403 Forbidden
// Controller-level exception handling (@ControllerAdvice) only applies to exceptions thrown inside controller methods or during controller request mapping.
// Spring Security filters (like your JwtAuthFilter) run before the request reaches the controller.
// If an exception occurs in the filter chain (e.g., invalid JWT, missing token), it never enters the controller. Instead, Spring Security internally triggers either:
// 	- JwtAuthenticationEntryPoint 	→ for 401 Unauthorized (unauthenticated access)
//  - JwtAccessDeniedHandler 		→ for 403 Forbidden (authenticated but insufficient privileges)
@ControllerAdvice
public class GlobalExceptionHandler {

	// ------------------- Custom API exceptions -------------------
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiResponse<Void>> handleApiException(ApiException ex) {
        ApiResponse<Void> response = new ApiResponse<>(ex.getMessage(), Instant.now(), null);
        return ResponseEntity.status(ex.getStatus().value()).body(response);
    }
    
    // ------------------- DTO Validation errors -------------------
    // Handle @Valid validation errors -> DTO Validation
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationErrors(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String field = ((FieldError) error).getField();
            String message = error.getDefaultMessage();
            errors.put(field, message);
        });
        ApiResponse<Map<String, String>> response = new ApiResponse<>("Validation failed", Instant.now(), errors);
        return ResponseEntity.badRequest().body(response);
    }
    
    // ------------------- Method parameter validation -------------------    
    // Method parameter @Validated validation errors
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleConstraintViolation(ConstraintViolationException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getConstraintViolations().forEach(cv -> errors.put(cv.getPropertyPath().toString(), cv.getMessage()));
        ApiResponse<Map<String, String>> response = new ApiResponse<>("Validation failed", Instant.now(), errors);
        return ResponseEntity.badRequest().body(response);
    }

    // ------------------- No endpoint found (404) -------------------
    /**
     * Handler for incorrect/non-existent endpoints. Ex: /api/v1/<incorrectURI>/1
     * Add below two properties in application.properties file
     *	spring.mvc.throw-exception-if-no-handler-found=true
     *	spring.web.resources.add-mappings=false
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleNoHandlerFound(NoHandlerFoundException ex) {
        ApiResponse<Void> response = new ApiResponse<>("Endpoint not found: " + ex.getRequestURL(), Instant.now(), null);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    // ------------------- Method not allowed (405) -------------------    
    // handle wrong HTTP method cases (e.g., sending POST /users/1 when only GET exists).
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResponse<Void>> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex) {
        String allowedMethods = String.join(", ", ex.getSupportedHttpMethods().stream().map(Enum::name).toList());
        ApiResponse<Void> response = new ApiResponse<>("Method " + ex.getMethod() + " not allowed. Allowed: " + allowedMethods, Instant.now(), null);
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(response);
    }

    // ------------------- Fallback for any uncaught exceptions -------------------    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleAll(Exception ex) {
    	ex.printStackTrace(); // optional — log for debugging
        ApiResponse<Void> response = new ApiResponse<>("An unexpected error occurred (Handled by Global Exception Handler)", Instant.now(), null);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}