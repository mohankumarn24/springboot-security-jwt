package net.projectsync.security.jwt.exception;

import org.springframework.http.HttpStatus;

// 403 Forbidden
public class ForbiddenException extends ApiException {

	private static final long serialVersionUID = 1L;

	public ForbiddenException(String message) {
		super(message, HttpStatus.FORBIDDEN);
	}
}