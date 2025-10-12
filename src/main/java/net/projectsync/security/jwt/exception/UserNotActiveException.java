package net.projectsync.security.jwt.exception;

import org.springframework.http.HttpStatus;

// 400 Bad Request
public class UserNotActiveException extends ApiException {

	private static final long serialVersionUID = 1L;

	public UserNotActiveException(String message) {
		super(message, HttpStatus.BAD_REQUEST);
	}
}