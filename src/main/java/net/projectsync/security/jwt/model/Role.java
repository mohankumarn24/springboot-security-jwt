package net.projectsync.security.jwt.model;

// Enum representing user roles.
public enum Role {
	ADMIN,
    USER;

	// Returns the role in Spring Security format: "ROLE_ADMIN", "ROLE_USER". Useful for authorities in SecurityContext.
    public String asSpringRole() {
        return "ROLE_" + this.name();
    }
}