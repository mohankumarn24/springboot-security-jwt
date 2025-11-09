package net.projectsync.security.jwt.exception;

import org.springframework.http.HttpStatus;
import lombok.Getter;

@Getter
public abstract class ApiException extends RuntimeException {
	
	private static final long serialVersionUID = 1L;
	private final HttpStatus status;

    protected ApiException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }
    
    protected ApiException(String message, Throwable cause, HttpStatus status) {
        super(message, cause); // now the cause is stored in the parent
        this.status = status;
    }
}

/*
The cause represents the original reason why the current exception occurred.

	try {
	    service.processPayment();
	} catch (PaymentGatewayException ex) {
	    throw new PaymentFailedException("Payment could not be processed", ex, HttpStatus.BAD_GATEWAY);
	}


Here:
 - DataIntegrityViolationException is the root cause
 - UserCreationException wraps it, giving higher-level context (like "user creation failed").
 - Example: Chained Stack Trace: 
 	log.error("Error occurred", e);

	com.example.exception.PaymentFailedException: Payment could not be processed
	at com.example.service.PaymentService.checkout(PaymentService.java:45)
	Caused by: com.example.gateway.PaymentGatewayException: Invalid card number
	at com.example.gateway.PaymentGateway.charge(PaymentGateway.java:32)

 - That Caused by: line appears because you passed the cause into super(message, cause).

*/

/*
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;

public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    public void createUser(String email) {
        try {
            // Simulate a database error (e.g., duplicate email)
            throw new DataIntegrityViolationException("Unique constraint violation: email already exists");

        } catch (DataIntegrityViolationException ex) {
            // Wrap low-level DB exception in a high-level business exception
            throw new ApiException("User creation failed", ex, HttpStatus.BAD_REQUEST);
        }
    }

    public static void main(String[] args) {
        UserService service = new UserService();

        try {
            service.createUser("mohan@example.com");
        } catch (ApiException e) {
            // Log both the message and full stack trace (including causes)
            log.error("Error creating user", e);

            // Optionally, print a simplified message for console/demo
            System.out.println("Error message only: " + e.getMessage());
            System.out.println("Root cause message: " + e.getCause().getMessage());
        }
    }
}

Logs:

2025-11-09 14:20:31.452 ERROR 12345 --- [main] c.e.UserService : Error creating user
com.example.ApiException: User creation failed
    at com.example.UserService.createUser(UserService.java:17)
    at com.example.UserService.main(UserService.java:26)
Caused by: org.springframework.dao.DataIntegrityViolationException: Unique constraint violation: email already exists
    at com.example.UserService.createUser(UserService.java:13)


Error message only: User creation failed
Root cause message: Unique constraint violation: email already exists

*/