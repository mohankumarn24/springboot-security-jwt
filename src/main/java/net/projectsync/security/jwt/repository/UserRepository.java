package net.projectsync.security.jwt.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import net.projectsync.security.jwt.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
	
	// Custom query method to fetch user by username
	Optional<User> findByUsername(String username);
}
