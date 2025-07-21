package com.shiraku.homeworkfourth.service;

import com.shiraku.homeworkfourth.model.entity.BlacklistedToken;
import com.shiraku.homeworkfourth.repository.BlacklistedTokenRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class TokenBlacklistService {

    private final BlacklistedTokenRepository repository;

    public TokenBlacklistService(BlacklistedTokenRepository repository) {
        this.repository = repository;
    }

    public void blacklist(String token, Instant expiryDate) {
        if (!repository.existsByToken(token)) {
            repository.save(BlacklistedToken.builder()
                    .token(token)
                    .expiryDate(expiryDate)
                    .build());
        }
    }

    public boolean isBlacklisted(String token) {
        return repository.existsByToken(token);
    }
}

