package net.projectsync.security.jwt.controller;

import java.time.Instant;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import net.projectsync.security.jwt.dto.ApiResponse;

@RestController
@RequestMapping("/api/user")
public class UserController {

	@GetMapping("/tasks")
	@PreAuthorize("hasRole('USER')") // ensures only USER role can access
	public ResponseEntity<ApiResponse<List<String>>> getTasks() {

		List<String> tasks = List.of("Task 1", "Task 2");
		ApiResponse<List<String>> response = new ApiResponse<>("User tasks fetched successfully", Instant.now(), tasks);
		return ResponseEntity.ok(response);
	}
}
