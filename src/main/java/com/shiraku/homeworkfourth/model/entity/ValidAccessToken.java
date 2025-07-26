package com.shiraku.homeworkfourth.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

import java.util.Date;
import java.util.UUID;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(of = {"id", "tokenHash", "userId"})
public class ValidAccessToken {
    @Id
    @GeneratedValue(generator = "UUID")
    @UuidGenerator(style = UuidGenerator.Style.RANDOM)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String tokenHash;

    @Column(nullable = false)
    private UUID userId;

    private Date issuedAt;
    private Date expiresAt;

    public ValidAccessToken(String tokenHash, UUID userId, Date issuedAt, Date expiresAt) {
        this.tokenHash = tokenHash;
        this.userId = userId;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }
}

