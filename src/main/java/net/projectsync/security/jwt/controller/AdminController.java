package net.projectsync.security.jwt.controller;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('ADMIN')") // ensures method-level security 
    public ResponseEntity<Map<String, Object>> getDashboard() {
    	
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Admin dashboard");
        response.put("timestamp", Instant.now());
        return ResponseEntity.ok(response);
    }
}

/**
 *  @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")         // Use hasRole for role-based access control 
 */