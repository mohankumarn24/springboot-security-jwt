package net.projectsync.security.jwt.aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class AuthLoggingAspect {

	private static final Logger logger = LoggerFactory.getLogger(AuthLoggingAspect.class);
	
	/*
	| Part                                     | Meaning                                                             					|
	| ---------------------------------------- | -------------------------------------------------------------------------------------- |
	| 'execution(...)'                         | The **designator** that tells Spring AOP to match method executions 					|
	| 'public *'                               | Any **public** method, regardless of its return type                					|
	| 'net.projectsync.security.jwt.service.*' | Any **class** under this package (but not subpackages)              					|
	| '.*(..)'                                 | Any **method name**, with **any number/type of parameters**         					|
	| '..*(..)'                                | Any **class** under this package + any of its subpackages (like .impl, .internal, etc.)| 
	*/
	
    // ---------------- Pointcut ----------------
    // Match all public methods in 'service' package
    // @Pointcut("execution(public * net.projectsync.security.jwt.service.*.*(..))")	// Any method under net.projectsync.security.jwt.service.*
    @Pointcut("execution(public * net.projectsync.security.jwt.service..*.*(..))")		// Any method under net.projectsync.security.jwt.service.* + it's subpackages
    public void allServiceMethods() {
    }

    // ---------------- Before advice ----------------
    @Before("allServiceMethods()")
    public void logBefore(JoinPoint joinPoint) {
        logger.info("[ASPECT BEFORE] Method: {}", joinPoint.getSignature().getName());
    }

    // ---------------- After advice ----------------
    @After("allServiceMethods()")
    public void logAfter(JoinPoint joinPoint) {
    	logger.info("[ASPECT AFTER] Method: {}", joinPoint.getSignature().getName());
    }

    // ---------------- AfterReturning advice ----------------
    @AfterReturning(pointcut = "allServiceMethods()", returning = "result")
    public void logAfterReturning(JoinPoint joinPoint, Object result) {    	
    	logger.info("[ASPECT AFTER RETURNING] Method: {}, returned: {}", 
    			joinPoint.getSignature().getName(), 
    			result != null ? result.toString() : "null");
    }

    // ---------------- AfterThrowing advice ----------------
    @AfterThrowing(pointcut = "allServiceMethods()", throwing = "error")
    public void logAfterThrowing(JoinPoint joinPoint, Throwable error) {
    	logger.info("[ASPECT AFTER THROWING] Method: {}, exception: {} - {}", 
    			joinPoint.getSignature().getName(), 
    			error.getClass().getSimpleName(), 
    			error.getMessage());
    }

    // ---------------- Around advice ----------------
    @Around("allServiceMethods()")
    public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {
        logger.info("[ASPECT AROUND BEFORE] Method: {}", joinPoint.getSignature().getName());
        try {
        	// return joinPoint.proceed();
            Object result = joinPoint.proceed();	// execute the method
            logger.info("[ASPECT AROUND AFTER] Method: {}, returned: {}", joinPoint.getSignature().getName(), result);
            return result;
        } catch (Throwable ex) {
        	logger.error("[ASPECT AROUND EXCEPTION] Method: {}, exception: {}", joinPoint.getSignature().getName(), ex.getMessage());
            throw ex;	// re-throw
        }
    }
}

/*

@Configuration
@EnableAspectJAutoProxy
public class AopConfig {

}

| Purpose                   | Required in Spring Boot? | Notes                               |
| ------------------------- | ------------------------ | ----------------------------------- |
| @EnableAspectJAutoProxy   | ❌ No                     | Boot enables AOP automatically      |
| Custom AopConfig          | ⚙️ Optional               | Use only for special proxy settings |
*/
