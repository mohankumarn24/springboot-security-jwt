package net.projectsync.security.jwt.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import net.projectsync.security.jwt.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
	
	Optional<RefreshToken> findByToken(String token);

	void deleteByUsername(String username);
}
