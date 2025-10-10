package net.projectsync.security.jwt.exception;

import org.springframework.http.HttpStatus;

// 409 Conflict
public class ConflictException extends ApiException {

	private static final long serialVersionUID = 1L;

	public ConflictException(String message) {
		super(message, HttpStatus.CONFLICT);
	}
}
