package net.projectsync.security.jwt.aspect;

import java.time.Instant;
import java.util.Date;
import javax.servlet.http.HttpServletRequest;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.annotation.RecentLoginRequired;
import net.projectsync.security.jwt.exception.ForbiddenException;
import net.projectsync.security.jwt.exception.UnauthorizedException;

/**
 * - Added for '/change-password' endpoint
 * - @RecentLoginRequired is a declarative security layer that helps enforce "recent login" policy for sensitive endpoints — clean, reusable, and separated from business logic
 * - Some actions (like viewing data) can be allowed with a long-lived JWT,
 * 	 but certain high-security actions (like changing passwords, deleting accounts, modifying MFA settings, etc.) should only be allowed shortly after a successful login.
 */
@Aspect
@Component
@RequiredArgsConstructor
public class RecentLoginAspect {

    private final HttpServletRequest httpServletRequest;

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Before("@annotation(recentLogin)")									// @annotation(recentLogin -> Spring passes the annotation instance to the advice, so you can read maxAgeSeconds() from it
    public void checkRecentLogin(RecentLoginRequired recentLogin) {		// @Before				   -> This code runs before any method annotated with @RecentLoginRequired
        String token = extractTokenFromRequest();
        if (token == null) {
            throw new UnauthorizedException("Missing access token");
        }

        Claims claims = Jwts.parser()
                            .setSigningKey(jwtSecret)
                            .parseClaimsJws(token)
                            .getBody();

        Instant issuedAt = claims.getIssuedAt().toInstant();
        Instant allowedTime = Instant.now().minusSeconds(recentLogin.maxAgeSeconds());

        if (issuedAt.isBefore(allowedTime)) {
        	// in case of any exception, the request never reaches '/change-password' endpoint
            throw new ForbiddenException("Token already expired/Invalid token");
        }
    }

    private String extractTokenFromRequest() {
        String authHeader = httpServletRequest.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}
