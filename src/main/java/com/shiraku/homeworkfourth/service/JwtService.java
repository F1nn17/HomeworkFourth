package com.shiraku.homeworkfourth.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.shiraku.homeworkfourth.config.JwtProperties;
import com.shiraku.homeworkfourth.model.entity.RefreshToken;
import com.shiraku.homeworkfourth.model.entity.RoleName;
import com.shiraku.homeworkfourth.model.entity.User;
import com.shiraku.homeworkfourth.model.entity.ValidAccessToken;
import com.shiraku.homeworkfourth.repository.RefreshTokenRepository;
import com.shiraku.homeworkfourth.repository.ValidAccessTokenRepository;
import jakarta.security.auth.message.AuthException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static java.util.Objects.hash;

@Service
public class JwtService {
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private final JwtProperties jwtProperties;
    private final ValidAccessTokenRepository validAccessTokenRepository;

    private final RefreshTokenRepository refreshTokenRepository;

    public JwtService(JwtProperties jwtProperties, ValidAccessTokenRepository validAccessTokenRepository, RefreshTokenRepository refreshTokenRepository) {
        this.jwtProperties = jwtProperties;
        this.validAccessTokenRepository = validAccessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Transactional
    public String generateToken(UUID userId, String login, Set<RoleName> roles, String ip, String userAgent) {
        long expirationMillis = jwtProperties.getExpiration();
        String secret = jwtProperties.getSecret();
        Algorithm algorithm = Algorithm.HMAC256(secret.getBytes(StandardCharsets.UTF_8));
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMillis);

        String jwt = JWT.create()
                .withSubject(userId.toString())
                .withClaim("login", login)
                .withClaim("roles", roles.stream().map(Enum::name).toList())
                .withClaim("ip", ip)
                .withClaim("ua", userAgent)
                .withIssuedAt(now)
                .withExpiresAt(expiry)
                .sign(algorithm);

        String tokenHash = String.valueOf(hash(jwt));
        validAccessTokenRepository.save(new ValidAccessToken(tokenHash, userId, now, expiry));

        return encrypt(jwt, secret);
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

    public boolean isTokenValid(String encryptedToken, String requestIp, String requestUserAgent) {
        try {
            DecodedJWT decoded = decodeToken(encryptedToken);

            String tokenIp = decoded.getClaim("ip").asString();
            String tokenUa = decoded.getClaim("ua").asString();

            return tokenIp != null && tokenUa != null &&
                    tokenIp.equals(requestIp) &&
                    tokenUa.equals(requestUserAgent);
        } catch (Exception e) {
            return false;
        }
    }

    @Transactional
    public RefreshToken createRefreshToken(User user) {
        String token = UUID.randomUUID().toString();

        Instant expiry = Instant.now().plus(Duration.ofDays(7));

        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .user(user)
                .expiryDate(expiry)
                .build();
        refreshTokenRepository.save(refreshToken);

        return refreshToken;
    }

    @Transactional
    public RefreshToken validate(String token) throws AuthException {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new AuthException("Refresh token expired");
        }

        return refreshToken;
    }

    @Transactional
    public void revokeAccessToken(String accessToken) {
        String decrypted = decrypt(accessToken, jwtProperties.getSecret());

        String tokenHash = String.valueOf(hash(decrypted));

        validAccessTokenRepository.deleteByTokenHash(tokenHash);
    }

    @Transactional
    public void revokeRefreshToken(String token) throws AuthException {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new AuthException("Token not found"));
        refreshTokenRepository.delete(refreshToken);
    }

    public boolean isAccessTokenWhitelisted(String token) {
        try {
            String decrypted = decrypt(token, jwtProperties.getSecret());
            String tokenHash = String.valueOf(hash(decrypted));
            return validAccessTokenRepository.existsByTokenHash(tokenHash);
        } catch (Exception e) {
            return false;
        }
    }


    private String extractClaim(String token, String claimKey) {
        DecodedJWT decodedJWT = decodeToken(token);
        return decodedJWT.getClaim(claimKey).asString();
    }

    private DecodedJWT decodeToken(String encryptedToken) {
        String secret = jwtProperties.getSecret();
        String jwt = decrypt(encryptedToken, secret);

        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret))
                .build();
        return verifier.verify(jwt);
    }

    private String encrypt(String plainText, String secret) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
            System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);

            return Base64.getEncoder().encodeToString(encryptedWithIv);
        } catch (Exception e) {
            throw new RuntimeException("Encryption error", e);
        }
    }

    private String decrypt(String encryptedText, String secret) {
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] iv = Arrays.copyOfRange(encryptedBytes, 0, GCM_IV_LENGTH);
            byte[] cipherText = Arrays.copyOfRange(encryptedBytes, GCM_IV_LENGTH, encryptedBytes.length);

            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            byte[] decrypted = cipher.doFinal(cipherText);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption error", e);
        }
    }

}
