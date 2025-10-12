package net.projectsync.security.jwt.dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import lombok.Data;

@Data
public class ChangePasswordRequest {

	@NotBlank(message = "Current password must not be blank")
	private String currentPassword;

	@NotBlank(message = "New password must not be blank")
	@Size(min = 8, max = 100, message = "New password must be between 8 and 100 characters")
	private String newPassword;

	@NotBlank(message = "Confirm password must not be blank")
	private String confirmPassword;
}
