package com.shiraku.homeworkfourth.repository;

import com.shiraku.homeworkfourth.model.entity.ValidAccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;

@Repository
public interface ValidAccessTokenRepository extends JpaRepository<ValidAccessToken, Integer> {
    void deleteAllByExpiresAtBefore(Date expiresAt);
    void deleteByTokenHash(String hash);
    boolean existsByTokenHash(String hash);
}
