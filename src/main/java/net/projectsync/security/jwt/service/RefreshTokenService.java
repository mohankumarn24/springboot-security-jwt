package net.projectsync.security.jwt.service;

import java.time.Instant;
import java.util.Optional;
import javax.transaction.Transactional;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;
import net.projectsync.security.jwt.entity.RefreshToken;
import net.projectsync.security.jwt.repository.RefreshTokenRepository;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public RefreshToken saveToken(String token, String username, Instant expiry) {
        if (expiry.isBefore(Instant.now())) {
            throw new IllegalArgumentException("Expiry must be in the future");
        }

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(token);
        refreshToken.setUsername(username);
        refreshToken.setExpiryDate(expiry);
        refreshToken.setRevoked(false);
        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }
    
    @Transactional
    public void revokeToken(String token) {
    	refreshTokenRepository.findByToken(token).ifPresent(t -> t.setRevoked(true));
    }

    @Transactional
    public void revokeTokenForUser(String username) {
    	refreshTokenRepository.deleteByUsername(username); // or update to revoke for history
    }

    public boolean isValid(String token) {
        return refreshTokenRepository.findByToken(token)
        							 .filter(t -> !t.isRevoked())
        							 .filter(t -> t.getExpiryDate().isAfter(Instant.now()))
        							 .isPresent();
    }
}
