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
import org.springframework.stereotype.Component;

@Aspect
@Component
public class AuthLoggingAspect {

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
    // Match all public methods in your service package
    // @Pointcut("execution(public * net.projectsync.security.jwt.service.*.*(..))")	// Any method under net.projectsync.security.jwt.service.*
    @Pointcut("execution(public * net.projectsync.security.jwt.service..*.*(..))")		// Any method under net.projectsync.security.jwt.service.* + its subpackages
    public void allServiceMethods() {
    }

    // ---------------- Before advice ----------------
    @Before("allServiceMethods()")
    public void logBefore(JoinPoint joinPoint) {
        System.out.println(String.format("[ASPECT BEFORE] Method: %s", joinPoint.getSignature().getName()));
    }

    // ---------------- After advice ----------------
    @After("allServiceMethods()")
    public void logAfter(JoinPoint joinPoint) {
        System.out.println(String.format("[ASPECT AFTER] Method: %s", joinPoint.getSignature().getName()));
    }

    // ---------------- AfterReturning advice ----------------
    @AfterReturning(pointcut = "allServiceMethods()", returning = "result")
    public void logAfterReturning(JoinPoint joinPoint, Object result) {
        System.out.println(String.format("[ASPECT AFTER RETURNING] Method: %s, returned: %s",
                joinPoint.getSignature().getName(),
                result != null ? result.toString() : "null"));
    }

    // ---------------- AfterThrowing advice ----------------
    @AfterThrowing(pointcut = "allServiceMethods()", throwing = "error")
    public void logAfterThrowing(JoinPoint joinPoint, Throwable error) {
        System.out.println(String.format("[ASPECT AFTER THROWING] Method: %s, exception: %s - %s",
                joinPoint.getSignature().getName(),
                error.getClass().getSimpleName(),
                error.getMessage()));
    }

    // ---------------- Around advice ----------------
    @Around("allServiceMethods()")
    public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {
        System.out.println(String.format("[ASPECT AROUND BEFORE] Method: %s", joinPoint.getSignature().getName()));
        Object result;
        try {
            result = joinPoint.proceed(); // execute the method
        } catch (Throwable ex) {
            System.out.println(String.format("[ASPECT AROUND EXCEPTION] Method: %s, exception: %s",
                    joinPoint.getSignature().getName(), ex.getMessage()));
            throw ex; // re-throw
        }
        System.out.println(String.format("[ASPECT AROUND AFTER] Method: %s, returned: %s",
                joinPoint.getSignature().getName(),
                result != null ? result.toString() : "null"));
        return result;
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
