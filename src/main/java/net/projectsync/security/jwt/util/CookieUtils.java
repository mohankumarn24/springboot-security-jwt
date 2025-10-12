package net.projectsync.security.jwt.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseCookie;
import net.projectsync.security.jwt.configuration.CookieProperties;
import net.projectsync.security.jwt.exception.BadRequestException;
import net.projectsync.security.jwt.exception.UnauthorizedException;

public final class CookieUtils {

	private CookieUtils() {
	}

	// Convenience method for auth cookies (refresh token, CSRF)
	public static String getAuthCookieValue(HttpServletRequest httpServletRequest, String cookieName) {
		return getCookieValue(httpServletRequest, cookieName, true);
	}

	// Convenience method for general cookies
	// String someCookie = CookieUtils.getCookieValue(request, "someCookie");
	public static String getCookieValue(HttpServletRequest httpServletRequest, String cookieName) {
		return getCookieValue(httpServletRequest, cookieName, false);
	}

	/**
	 * Fetch cookie value by cookie name
	 * 	- Throws BadRequestException if request has no cookies at all
	 *  - Throws UnauthorizedException if the requested cookie is missing or empty (auth-related use-case).
	 */
	public static String getCookieValue(HttpServletRequest httpServletRequest, String cookieName,
			boolean isAuthCookie) {

		if (httpServletRequest.getCookies() == null || httpServletRequest.getCookies().length == 0) {
			if (isAuthCookie) {
				throw new UnauthorizedException("Authentication cookies not found");	// if user hits '/logout' twice, throws 'Authentication cookies not found' instead of 'User already logged out'. Use 'getAuthCookiesLogout()'
			}
			throw new BadRequestException("No cookies found in request");
		}

		for (Cookie cookie : httpServletRequest.getCookies()) {
			if (cookieName.equals(cookie.getName())) {
				if (cookie.getValue() == null || cookie.getValue().isBlank()) {
					if (isAuthCookie) {
						throw new UnauthorizedException("Authentication cookie '" + cookieName + "' is empty");
					}
					throw new BadRequestException("Cookie '" + cookieName + "' is empty");
				}
				return cookie.getValue();
			}
		}

		if (isAuthCookie) {
			throw new UnauthorizedException("Required authentication cookie '" + cookieName + "' not found");
		}
		throw new BadRequestException("Required cookie '" + cookieName + "' not found");
	}

	public static AuthCookies getAuthCookies(HttpServletRequest httpServletRequest, CookieProperties cookieProperties) {
		
		String refreshToken = getAuthCookieValue(httpServletRequest, cookieProperties.getRefresh().getName());
		String csrfToken = getAuthCookieValue(httpServletRequest, cookieProperties.getCsrf().getName());
		
		return new AuthCookies(refreshToken, csrfToken);
	}

	// added to avoid 'User already log'
	public static AuthCookies getAuthCookiesLogout(HttpServletRequest request, CookieProperties cookieProperties) {
		
	    String refreshToken = null;
	    String csrfToken = null;

	    Cookie[] cookies = request.getCookies();
	    if (cookies != null) {
	        for (Cookie cookie : cookies) {
	            if (cookie.getName().equals(cookieProperties.getRefresh().getName())) {
	                refreshToken = cookie.getValue();
	            } else if (cookie.getName().equals(cookieProperties.getCsrf().getName())) {
	                csrfToken = cookie.getValue();
	            }
	        }
	    }

	    return new AuthCookies(refreshToken, csrfToken);
	}

	
	/** JDK 11 compatible inner class to hold auth cookies */
	public static class AuthCookies {
		
		private final String refreshToken;
		private final String csrfToken;

		public AuthCookies(String refreshToken, String csrfToken) {
			this.refreshToken = refreshToken;
			this.csrfToken = csrfToken;
		}

		public String getRefreshToken() {
			return refreshToken;
		}

		public String getCsrfToken() {
			return csrfToken;
		}
	}
	
	/* 
	 * Create a ResponseCookie with standard settings
	 * 
	 * @param cookieProps CookieProperties.Cookie (name, path, maxAge)
	 * @param cookieValue Cookie value
	 * @param isHttpOnly HttpOnly flag
	 * @param isSecure HTTPS flag
	 * @param sameSite "Strict", "Lax", or "None"
	 * @return
	 */
    public static ResponseCookie createCookie(CookieProperties.Cookie cookieProps, String cookieValue, boolean isHttpOnly, boolean isSecure, String sameSite) {
    	
    	return ResponseCookie.from(cookieProps.getName(), cookieValue)
    			.httpOnly(isHttpOnly)
    			.secure(isSecure)
    			.sameSite(sameSite)
    			.path(cookieProps.getPath())
    			.maxAge(cookieProps.getMaxAgeSeconds())
    			.build();
    }

    // Convenience method to clear a cookie (set maxAge=0)
    public static ResponseCookie clearCookie(CookieProperties.Cookie cookieProps, boolean isHttpOnly, boolean isSecure, String sameSite) {
    	
    	return ResponseCookie.from(cookieProps.getName(), "")
    			.httpOnly(isHttpOnly)
    			.secure(isSecure)
    			.sameSite(sameSite)
    			.path(cookieProps.getPath())
    			.maxAge(0)
    			.build();
    }
}
