package net.projectsync.security.jwt.annotation;

import java.lang.annotation.*;

/**
 * Added for '/change-password' endpoint
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RecentLoginRequired {
    /**
     * Maximum allowed age of the JWT in seconds for this endpoint.
     */
    long maxAgeSeconds() default 300; // default 5 minutes
}

