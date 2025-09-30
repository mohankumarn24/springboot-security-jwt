package net.projectsync.security.jwt.service;

import java.time.Instant;
import java.util.Optional;
import javax.transaction.Transactional;
import org.springframework.stereotype.Service;
import net.projectsync.security.jwt.entity.RefreshToken;
import net.projectsync.security.jwt.repository.RefreshTokenRepository;

@Service
public class RefreshTokenService {

	private final RefreshTokenRepository repo;

	public RefreshTokenService(RefreshTokenRepository repo) {
		this.repo = repo;
	}

	// Save refresh token
	public RefreshToken saveToken(String token, String username, Instant expiry) {
		RefreshToken r = new RefreshToken();
		r.setToken(token);
		r.setUsername(username);
		r.setExpiryDate(expiry);
		r.setRevoked(false);
		return repo.save(r);
	}

	// Find by token
	public Optional<RefreshToken> findByToken(String token) {
		return repo.findByToken(token);
	}

	// Revoke a single token
	@Transactional
	public void revokeToken(String token) {
		repo.findByToken(token).ifPresent(t -> {
			t.setRevoked(true);
			repo.save(t);
		});
	}

	// Revoke all tokens for a user
	@Transactional
	public void revokeTokenForUser(String username) {
		repo.deleteByUsername(username);
	}

	// Check if token is valid (not revoked and not expired)
	public boolean isValid(String token) {
		return repo.findByToken(token).filter(t -> !t.isRevoked()).filter(t -> t.getExpiryDate().isAfter(Instant.now()))
				.isPresent();
	}
}