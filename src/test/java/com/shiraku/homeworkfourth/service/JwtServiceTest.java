package com.shiraku.homeworkfourth.service;

import com.shiraku.homeworkfourth.config.JwtProperties;
import com.shiraku.homeworkfourth.model.entity.RefreshToken;
import com.shiraku.homeworkfourth.model.entity.RoleName;
import com.shiraku.homeworkfourth.model.entity.User;
import com.shiraku.homeworkfourth.repository.RefreshTokenRepository;
import com.shiraku.homeworkfourth.repository.ValidAccessTokenRepository;
import jakarta.security.auth.message.AuthException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private ValidAccessTokenRepository validAccessTokenRepository;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @InjectMocks
    private JwtService jwtService;

    private final String secret = "12345678901234567890123456789012";

    private final UUID userId = UUID.randomUUID();
    private final String login = "john";
    private final Set<RoleName> roles = Set.of(RoleName.GUEST);
    private final String ip = "127.0.0.1";
    private final String userAgent = "JUnit";

    @BeforeEach
    void setUp() {
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecret(secret);
        jwtProperties.setExpiration(3600000L);

        jwtService = new JwtService(jwtProperties, validAccessTokenRepository, refreshTokenRepository);
    }

    @Test
    void testGenerateAndValidateToken() {
        String encrypted = jwtService.generateToken(userId, login, roles, ip, userAgent);

        assertNotNull(encrypted);

        assertTrue(jwtService.isTokenValid(encrypted, ip, userAgent));
        assertEquals(login, jwtService.extractLogin(encrypted));
        assertEquals(userId, jwtService.getUserId(encrypted));
        assertTrue(jwtService.extractRoles(encrypted).contains("GUEST"));
        assertNotNull(jwtService.extractExpiration(encrypted));
    }

    @Test
    void testEncryptAndDecrypt() {
        String jwt = "test-payload";
        String encrypted = invokeEncrypt(jwt);
        String decrypted = invokeDecrypt(encrypted);

        assertEquals(jwt, decrypted);
    }

    @Test
    void testRevokeAccessToken() {
        String token = jwtService.generateToken(userId, login, roles, ip, userAgent);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        jwtService.revokeAccessToken(token);

        verify(validAccessTokenRepository).deleteByTokenHash(captor.capture());

        String actualHash = captor.getValue();
        assertNotNull(actualHash);
    }


    @Test
    void testCreateRefreshToken() {
        User user = new User();
        user.setId(userId);
        user.setLogin(login);

        RefreshToken expected = RefreshToken.builder()
                .id(UUID.randomUUID())
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiryDate(Instant.now().plus(Duration.ofDays(7)))
                .build();

        when(refreshTokenRepository.save(any())).thenReturn(expected);

        RefreshToken result = jwtService.createRefreshToken(user);

        assertNotNull(result.getToken());
        assertEquals(user, result.getUser());
    }

    @Test
    void testValidateValidRefreshToken() throws AuthException {
        RefreshToken token = new RefreshToken();
        token.setToken("abc");
        token.setExpiryDate(Instant.now().plusSeconds(60));

        when(refreshTokenRepository.findByToken("abc")).thenReturn(Optional.of(token));

        RefreshToken validated = jwtService.validate("abc");

        assertEquals(token, validated);
    }

    @Test
    void testValidateExpiredRefreshToken() {
        RefreshToken token = new RefreshToken();
        token.setToken("abc");
        token.setExpiryDate(Instant.now().minusSeconds(10));

        when(refreshTokenRepository.findByToken("abc")).thenReturn(Optional.of(token));

        assertThrows(AuthException.class, () -> jwtService.validate("abc"));
        verify(refreshTokenRepository).delete(token);
    }

    @Test
    void testRevokeRefreshToken() throws Exception {
        RefreshToken token = new RefreshToken();
        token.setToken("abc");

        when(refreshTokenRepository.findByToken("abc")).thenReturn(Optional.of(token));

        jwtService.revokeRefreshToken("abc");

        verify(refreshTokenRepository).delete(token);
    }

    // 🔒 Вспомогательные методы для прямого доступа
    private String invokeEncrypt(String raw) {
        return ReflectionTestUtils.invokeMethod(jwtService, "encrypt", raw, secret);
    }

    private String invokeDecrypt(String enc) {
        return ReflectionTestUtils.invokeMethod(jwtService, "decrypt", enc, secret);
    }
}

