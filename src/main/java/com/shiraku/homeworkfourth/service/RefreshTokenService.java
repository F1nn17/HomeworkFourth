package com.shiraku.homeworkfourth.service;

import com.shiraku.homeworkfourth.model.entity.RefreshToken;
import com.shiraku.homeworkfourth.model.entity.User;
import com.shiraku.homeworkfourth.repository.RefreshTokenRepository;
import jakarta.security.auth.message.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository repository;

    public RefreshToken createToken(User user) {
        RefreshToken token = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiryDate(Instant.now().plusSeconds(7 * 24 * 60 * 60))
                .build();

        return repository.save(token);
    }

    public RefreshToken validate(String token) throws AuthException {
        RefreshToken refreshToken = repository.findByToken(token)
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            repository.delete(refreshToken);
            throw new AuthException("Refresh token expired");
        }

        return refreshToken;
    }

    public void revoke(String token) throws AuthException {
        RefreshToken refreshToken = repository.findByToken(token)
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        repository.delete(refreshToken);
    }

    public void revokeAllForUser(UUID userId) {
        repository.deleteByUserId(userId);
    }
}
