package net.projectsync.security.jwt.util;

import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class ResponseUtil {

    private ResponseUtil() {} // prevent instantiation

    public static <T> ResponseEntity<ApiResponse<T>> buildResponse(String message, T data, HttpStatus httpStatus) {
        ApiResponse<T> response = new ApiResponse<>(message, Instant.now(), data);
        return ResponseEntity.status(httpStatus.value()).body(response);
    }
}