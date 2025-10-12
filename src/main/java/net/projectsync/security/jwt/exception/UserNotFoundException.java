package net.projectsync.security.jwt.exception;

import org.springframework.http.HttpStatus;

// 404 Requested resource not found
public class UserNotFoundException extends ApiException {

	private static final long serialVersionUID = 1L;

	public UserNotFoundException(String message) {
		super(message, HttpStatus.NOT_FOUND);
	}
}
