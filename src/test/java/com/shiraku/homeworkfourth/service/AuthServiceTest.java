package com.shiraku.homeworkfourth.service;

import com.shiraku.homeworkfourth.model.dto.JwtTokenServiceResponse;
import com.shiraku.homeworkfourth.model.dto.RegisterRequest;
import com.shiraku.homeworkfourth.model.entity.RefreshToken;
import com.shiraku.homeworkfourth.model.entity.RoleName;
import com.shiraku.homeworkfourth.model.entity.User;
import com.shiraku.homeworkfourth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthService authService;

    @Test
    void testRegisterUser() {
        RegisterRequest request = new RegisterRequest("login", "pass", "email@test.com", Set.of("GUEST"));

        when(passwordEncoder.encode("pass")).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        authService.register(request);
    }

    @Test
    void testAuthenticateSuccess() {
        String login = "user";
        String password = "123";
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setLogin(login);
        user.setPassword("hashed");
        user.setRoles(Set.of(RoleName.GUEST));

        when(userRepository.findByLogin(login)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(password, "hashed")).thenReturn(true);
        when(jwtService.generateToken(any(), any(), any(), any(), any())).thenReturn("access-token");
        when(jwtService.createRefreshToken(user)).thenReturn(new RefreshToken(UUID.randomUUID(), "refresh-token", user, Instant.now().plusSeconds(3600)));

        JwtTokenServiceResponse response = authService.authenticate(login, password, "127.0.0.1", "agent");

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isEqualTo("refresh-token");
    }

}

