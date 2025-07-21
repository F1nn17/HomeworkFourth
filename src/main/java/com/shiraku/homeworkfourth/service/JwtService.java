package com.shiraku.homeworkfourth.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.shiraku.homeworkfourth.config.JwtProperties;
import com.shiraku.homeworkfourth.model.entity.RoleName;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Service
public class JwtService {
    private final JwtProperties jwtProperties;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public String generateToken(UUID userId, String login, Set<RoleName> roles) {
        long expirationMillis = jwtProperties.getExpiration();
        String secret = jwtProperties.getSecret();

        Algorithm algorithm = Algorithm.HMAC256(secret.getBytes(StandardCharsets.UTF_8));
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMillis);

        return JWT.create()
                .withSubject(userId.toString())
                .withClaim("login", login)
                .withClaim("roles", roles.stream().map(Enum::name).toList())
                .withIssuedAt(now)
                .withExpiresAt(expiry)
                .sign(algorithm);
    }

    public UUID getUserId(String token) {
        String subject = extractClaim(token, "sub");
        return UUID.fromString(subject);
    }

    public String extractLogin(String token) {
        return extractClaim(token, "login");
    }

    public Set<String> extractRoles(String token) {
        DecodedJWT decodedJWT = decodeToken(token);
        List<String> rolesList = decodedJWT.getClaim("roles").asList(String.class);
        if (rolesList == null) {
            return Collections.emptySet();
        }
        return new HashSet<>(rolesList);
    }

    public Instant extractExpiration(String token) {
        DecodedJWT decodedJWT = decodeToken(token);
        return decodedJWT.getExpiresAt().toInstant();
    }

    public boolean isTokenValid(String token) {
        String secret = jwtProperties.getSecret();
        try {
            JWT.require(Algorithm.HMAC256(secret.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .verify(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String extractClaim(String token, String claimKey) {
        DecodedJWT decodedJWT = decodeToken(token);
        return decodedJWT.getClaim(claimKey).asString();
    }

    private DecodedJWT decodeToken(String token) {
        String secret = jwtProperties.getSecret();
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret))
                .build();
        return verifier.verify(token);
    }
}
