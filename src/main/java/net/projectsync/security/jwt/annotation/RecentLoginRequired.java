package net.projectsync.security.jwt.annotation;

import java.lang.annotation.*;

/**
 * Added for '/change-password' endpoint
 */
@Target(ElementType.METHOD)						// You can only put this annotation on methods
@Retention(RetentionPolicy.RUNTIME)				// Available at runtime (needed for Aspect). The annotation is kept in the bytecode at runtime, so your Aspect can read it using reflection
@Documented										// Added for Javadocs
public @interface RecentLoginRequired {

    long maxAgeSeconds() default 300; 			// maxAgeSeconds defines how recent the login must be (default 5 minutes)
}

