package net.projectsync.security.jwt.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.configuration.CookieProperties;
import net.projectsync.security.jwt.dto.SignInRequest;
import net.projectsync.security.jwt.dto.SignupRequest;
import net.projectsync.security.jwt.dto.TokenResponse;
import net.projectsync.security.jwt.dto.UserDTO;
import net.projectsync.security.jwt.service.AuthService;
import net.projectsync.security.jwt.util.ApiResponse;
import net.projectsync.security.jwt.util.CookieUtils;
import net.projectsync.security.jwt.util.CookieUtils.AuthCookies;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthService authService;
	private final CookieProperties cookieProperties;

	@PostMapping("/signup")
	public ResponseEntity<ApiResponse<UserDTO>> signup(HttpServletRequest httpServletRequest,
			@Validated @RequestBody SignupRequest signupRequest, HttpServletResponse httpServletResponse) {

		return authService.signup(httpServletRequest, httpServletResponse, signupRequest);
	}

	@PostMapping("/signin")
	public ResponseEntity<ApiResponse<TokenResponse>> signin(HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, @RequestBody SignInRequest signInRequest) {

		return authService.signin(httpServletRequest, httpServletResponse, signInRequest);
	}

	@PostMapping("/refresh")
	public ResponseEntity<ApiResponse<TokenResponse>> refresh(HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse,
			// @CookieValue(name = REFRESH_COOKIE_NAME, required = false) String
			// oldRefreshToken,
			// @CookieValue(name = CSRF_COOKIE_NAME, required = false) String
			// csrfCookieValue,
			@RequestHeader(value = "X-XSRF-TOKEN", required = false) String csrfHeaderValue) {

		AuthCookies authCookies = CookieUtils.getAuthCookies(httpServletRequest, cookieProperties);
		return authService.refresh(httpServletRequest, httpServletResponse, authCookies.getRefreshToken(),
				authCookies.getCsrfToken(), csrfHeaderValue);
	}

	@PostMapping("/logout")
	public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse,
			// @CookieValue(name = REFRESH_COOKIE_NAME, required = false) String
			// refreshToken,
			// @CookieValue(name = CSRF_COOKIE_NAME, required = false) String
			// csrfCookieValue,
			@RequestHeader(value = "X-XSRF-TOKEN", required = false) String csrfHeaderValue) {

		// AuthCookies authCookies = CookieUtils.getAuthCookies(httpServletRequest, cookieProperties);		// if user hits '/logout' twice, throws 'Authentication cookies not found' instead of 'User already logged out'. Use 'getAuthCookiesLogout()'
		AuthCookies authCookies = CookieUtils.getAuthCookiesLogout(httpServletRequest, cookieProperties);
		return authService.logout(httpServletRequest, httpServletResponse, authCookies.getRefreshToken(),
				authCookies.getCsrfToken(), csrfHeaderValue);
	}

}
