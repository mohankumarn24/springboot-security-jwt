package net.projectsync.security.jwt.mapper;

import net.projectsync.security.jwt.dto.UserDTO;
import net.projectsync.security.jwt.entity.User;
import net.projectsync.security.jwt.model.Role;

public class UserMapper {

    // Convert User entity to UserDTO
    public static UserDTO toDTO(User user) {
    	
        if (user == null) return null;

        return new UserDTO(
                user.getId(),
                user.getUsername(),
                user.getRole().name(), // convert enum to string
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }

    // Optional: convert UserDTO to entity (e.g., for updates)
    public static User toEntity(UserDTO dto, User existingUser) {
        if (dto == null) return null;

        existingUser.setUsername(dto.getUsername());
        existingUser.setRole(Role.valueOf(dto.getRole()));
        // Don't set password here
        return existingUser;
    }
}
