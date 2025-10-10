package net.projectsync.security.jwt.exception;

import org.springframework.http.HttpStatus;
import lombok.Getter;

@Getter
public abstract class ApiException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	private final HttpStatus status;

    protected ApiException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }
}
