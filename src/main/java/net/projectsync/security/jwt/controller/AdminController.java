package net.projectsync.security.jwt.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import net.projectsync.security.jwt.util.ApiResponse;
import net.projectsync.security.jwt.util.ResponseUtil;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('ADMIN')")  // Method-level security
    public ResponseEntity<ApiResponse<Void>> getDashboard() {
        return ResponseUtil.buildResponse("Admin dashboard", null, HttpStatus.OK);
    }
}

/**
 * Optional example for multiple roles:
 * @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
 */
