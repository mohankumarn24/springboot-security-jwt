package net.projectsync.security.jwt.exception;

public class RecentLoginRequiredException extends RuntimeException {
    public RecentLoginRequiredException(String message) {
        super(message);
    }
}

