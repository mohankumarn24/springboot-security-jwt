package net.projectsync.security.jwt.model;

public enum Role {
    ADMIN,
    USER;

    // Optional: get Spring Security format
    public String asSpringRole() {
        return "ROLE_" + this.name();
    }
}
