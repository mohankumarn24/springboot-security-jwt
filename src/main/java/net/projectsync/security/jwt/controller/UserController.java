package net.projectsync.security.jwt.controller;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @GetMapping("/tasks")
    @PreAuthorize("hasRole('USER')") // adds method-level security
    public ResponseEntity<Map<String, Object>> getTasks() {
        Map<String, Object> response = new HashMap<>();
        response.put("tasks", List.of("Task 1", "Task 2"));
        response.put("timestamp", Instant.now());
        return ResponseEntity.ok(response);
    }
}