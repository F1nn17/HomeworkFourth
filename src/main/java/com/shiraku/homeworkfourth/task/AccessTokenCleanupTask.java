package com.shiraku.homeworkfourth.task;

import com.shiraku.homeworkfourth.repository.ValidAccessTokenRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;

@Component
public class AccessTokenCleanupTask {

    private final ValidAccessTokenRepository repository;

    public AccessTokenCleanupTask(ValidAccessTokenRepository repository) {
        this.repository = repository;
    }

    @Scheduled(fixedDelay = 5 * 60 * 1000)
    public void cleanExpiredTokens() {
        repository.deleteAllByExpiresAtBefore(Date.from(Instant.now()));
    }
}

