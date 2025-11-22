package net.projectsync.security.jwt.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.annotation.RecentLoginRequired;
import net.projectsync.security.jwt.configuration.CookieProperties;
import net.projectsync.security.jwt.dto.ChangePasswordRequest;
import net.projectsync.security.jwt.dto.SignInRequest;
import net.projectsync.security.jwt.dto.SignupRequest;
import net.projectsync.security.jwt.dto.TokenResponse;
import net.projectsync.security.jwt.dto.UserDTO;
import net.projectsync.security.jwt.service.AuthService;
import net.projectsync.security.jwt.service.JwtService;
import net.projectsync.security.jwt.util.ApiResponse;
import net.projectsync.security.jwt.util.CookieUtils;
import net.projectsync.security.jwt.util.CookieUtils.AuthCookies;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated  																							// Enables method-level parameter validation. Recommended approach is to add at controller level
public class AuthController {

	private final AuthService authService;
	private final CookieProperties cookieProperties;
	private final JwtService jwtService;

	@PostMapping("/signup")
	public ResponseEntity<ApiResponse<UserDTO>> signup(
													HttpServletRequest httpServletRequest,
													HttpServletResponse httpServletResponse,
													@RequestBody @Valid SignupRequest signupRequest) { 	// @Valid triggers validation on the fields inside SignupRequest ie., username, password
																										// If you don’t add @Valid on the @RequestBody SignupRequest signupRequest, then Spring will NOT trigger bean validation for the fields inside SignupRequest
																										// No automatic validation is performed on - @NotBlank, @Size, @Pattern
																										// This means invalid or empty values will not cause any validation error

		return authService.signup(
				httpServletRequest, 
				httpServletResponse, 
				signupRequest);
	}

	@PostMapping("/signin")
	public ResponseEntity<ApiResponse<TokenResponse>> signin(
													HttpServletRequest httpServletRequest,
													HttpServletResponse httpServletResponse, 
													@RequestBody @Valid SignInRequest signInRequest) {	// @Valid triggers validation on the fields inside signInRequest ie., username, password

		return authService.signin(
				httpServletRequest, 
				httpServletResponse, 
				signInRequest);
	}

	// @Validated 																						// either add at class-level or method-level to trigger validation
	@PostMapping("/refresh")
	public ResponseEntity<ApiResponse<TokenResponse>> refresh(
													HttpServletRequest httpServletRequest,
													HttpServletResponse httpServletResponse,
													// @CookieValue(name = REFRESH_COOKIE_NAME, required = false) String oldRefreshToken,
													// @CookieValue(name = CSRF_COOKIE_NAME, required = false) String csrfCookieValue,
													// @RequestParam @Min(1) @Max(100) int version, 	// @Validated triggers validation on request params ie., /api/auth/refresh?version=0
													@RequestHeader(value = "X-XSRF-TOKEN", required = true) String csrfHeaderValue) {

		AuthCookies authCookies = CookieUtils.getAuthCookies(httpServletRequest, cookieProperties);
		return authService.refresh(
				httpServletRequest, 
				httpServletResponse, 
				authCookies.getRefreshToken(),
				authCookies.getCsrfToken(), 
				csrfHeaderValue);
		
		/*
		 * You can use request.getHeader("X-XSRF-TOKEN") instead of @RequestHeader, and it will work the same
		 * 
		 * | --------------------- | ------ | ---------------------------- | ------------------------------- |
		 * | Option                | Works? | Pros                         | Cons                            |
		 * | --------------------- | ------ | ---------------------------- | ------------------------------- |
		 * |  @RequestHeader       |  Yes   | Auto-validation, clean, safe | None                            |
		 * |  request.getHeader()  |  Yes   | Manual control               | You must validate null yourself |
		 * | --------------------- | ------ | ---------------------------- | ------------------------------- |
		 */
	}

	@PostMapping("/logout")
	public ResponseEntity<ApiResponse<Void>> logout(
													HttpServletRequest httpServletRequest,
													HttpServletResponse httpServletResponse,
													// @CookieValue(name = REFRESH_COOKIE_NAME, required = false) String refreshToken,
													// @CookieValue(name = CSRF_COOKIE_NAME, required = false) String csrfCookieValue,
													// @RequestParam @NotBlank String reason), // validate non-blank parameter
													@RequestHeader(value = "X-XSRF-TOKEN", required = true) String csrfHeaderValue) {

		// AuthCookies authCookies = CookieUtils.getAuthCookies(httpServletRequest, cookieProperties);		// if user hits '/logout' twice, throws 'Authentication cookies not found' instead of 'User already logged out'. Use 'getAuthCookiesLogout()'
		AuthCookies authCookies = CookieUtils.getAuthCookiesLogout(httpServletRequest, cookieProperties);
		return authService.logout(
				httpServletRequest, 
				httpServletResponse, 
				authCookies.getRefreshToken(),
				authCookies.getCsrfToken(), 
				csrfHeaderValue);
	}
	
	@PostMapping("/change-password")
	// Check that the user’s JWT token was issued in the last 300 seconds before allowing this method to run.
	// Added files - RecentLoginRequired custom annotation, RecentLoginAspect aspect, ChangePasswordRequest DTO, UserNotActiveException, UserNotFoundException	
	@RecentLoginRequired(maxAgeSeconds = 300)	// A custom annotation that triggers the RecentLoginAspect before executing this method. It doesn’t do anything by itself — it’s just metadata  
	public ResponseEntity<ApiResponse<Void>> changePassword(
													HttpServletRequest httpServletRequest,
													HttpServletResponse httpServletResponse,
													@RequestBody @Valid  ChangePasswordRequest changePasswordRequest,
											        @RequestHeader(value = "X-XSRF-TOKEN", required = true) String csrfHeaderValue) {
		
	    // Extract CSRF cookie
		AuthCookies authCookies = CookieUtils.getAuthCookiesLogout(httpServletRequest, cookieProperties);
	    return authService.changePassword(
	    		httpServletRequest, 
	    		httpServletResponse,
	    		authCookies.getRefreshToken(), 	    		
	    		authCookies.getCsrfToken(), 
	    		csrfHeaderValue, 
	    		changePasswordRequest);
	}
}