package net.projectsync.security.jwt.annotation;

import java.lang.annotation.*;

/**
 * Added for '/change-password' endpoint
 */
@Target(ElementType.METHOD)						// You can only put this annotation on methods
@Retention(RetentionPolicy.RUNTIME)				// Available at runtime (needed for Aspect). The annotation is kept in the bytecode at runtime, so your Aspect can read it using reflection
@Documented										// Added for Javadocs
public @interface RecentLoginRequired {			// declares a custom annotation

    long maxAgeSeconds() default 300; 			// maxAgeSeconds defines how recent the login must be (default 5 minutes)
}

/*
1. @Retention(RetentionPolicy.RUNTIME)
	- Purpose: Defines how long the annotation is retained
	- RUNTIME → the annotation is available in bytecode at runtime, which is required if you want to access it via reflection or an Aspect (Spring AOP) during method execution
	- Other options:
		-- CLASS → retained in bytecode but not available at runtime
		-- SOURCE → discarded after compilation
	
2. How it is used:

	@RecentLoginRequired(maxAgeSeconds = 600)
	public void sensitiveAction() {
	    // only accessible if login is within last 10 minutes
	}

	- If maxAgeSeconds is omitted, it uses the default 300 seconds (5 minutes)
	- Typically, you would have an Aspect or interceptor that:
		-- Checks the last login time of the current user
		-- Compares it with the current time
		-- Throws an exception or denies access if the login is too old	
*/