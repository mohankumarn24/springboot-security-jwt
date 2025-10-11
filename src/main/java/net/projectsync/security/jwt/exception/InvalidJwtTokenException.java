package net.projectsync.security.jwt.exception;

// Represents a JWT validation failure.
// Can be thrown for expired, malformed, or tampered tokens.
public class InvalidJwtTokenException extends UnauthorizedException {

    private static final long serialVersionUID = 1L;

    public InvalidJwtTokenException(String message) {
        super(message);
    }

    public InvalidJwtTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}

