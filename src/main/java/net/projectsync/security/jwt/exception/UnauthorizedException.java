package net.projectsync.security.jwt.exception;

import org.springframework.http.HttpStatus;

// 401 Unauthorized
public class UnauthorizedException extends ApiException {

	private static final long serialVersionUID = 1L;

	public UnauthorizedException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
}