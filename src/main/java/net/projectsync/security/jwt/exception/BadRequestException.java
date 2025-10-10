package net.projectsync.security.jwt.exception;

import org.springframework.http.HttpStatus;

// 400 Bad Request
public class BadRequestException extends ApiException {

	private static final long serialVersionUID = 1L;

	public BadRequestException(String message) {
		super(message, HttpStatus.BAD_REQUEST);
	}
}