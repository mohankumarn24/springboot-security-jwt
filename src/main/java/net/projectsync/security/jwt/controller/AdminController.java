package net.projectsync.security.jwt.controller;

import java.time.Instant;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import net.projectsync.security.jwt.dto.ApiResponse;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('ADMIN')")  // ensures method-level security 
    public ResponseEntity<ApiResponse<Void>> getDashboard() {

        ApiResponse<Void> response = new ApiResponse<>(
                "Admin dashboard",
                Instant.now(),
                null  // no additional data
        );
        return ResponseEntity.ok(response);
    }
}


/**
 *  @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")         // Use hasRole for role-based access control 
 */