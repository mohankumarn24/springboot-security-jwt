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
import net.projectsync.security.jwt.exception.RecentLoginRequiredException;

/**
 * Added for '/change-password' endpoint
 */
@Aspect
@Component
@RequiredArgsConstructor
public class RecentLoginAspect {

    private final HttpServletRequest httpServletRequest;

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Before("@annotation(recentLogin)")
    public void checkRecentLogin(RecentLoginRequired recentLogin) {
        String token = extractTokenFromRequest();
        if (token == null) {
            throw new RecentLoginRequiredException("Missing access token");
        }

        Claims claims = Jwts.parser()
                            .setSigningKey(jwtSecret)
                            .parseClaimsJws(token)
                            .getBody();

        Date issuedAt = claims.getIssuedAt();
        Instant allowedTime = Instant.now().minusSeconds(recentLogin.maxAgeSeconds());

        if (issuedAt.toInstant().isBefore(allowedTime)) {
            throw new RecentLoginRequiredException("Token already expired/Invalid token");
        }
    }

    private String extractTokenFromRequest() {
        String bearer = httpServletRequest.getHeader("Authorization");
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }
}
