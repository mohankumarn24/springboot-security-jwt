package net.projectsync.security.jwt.controller;

import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import net.projectsync.security.jwt.util.ApiResponse;
import net.projectsync.security.jwt.util.ResponseUtil;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @GetMapping("/tasks")
    @PreAuthorize("hasRole('USER')")  // Method-level security
    public ResponseEntity<ApiResponse<List<String>>> getTasks() {
        return ResponseUtil.buildResponse("User tasks fetched successfully", null, HttpStatus.OK);
    }
}
