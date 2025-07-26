package com.shiraku.homeworkfourth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shiraku.homeworkfourth.model.dto.LoginRequest;
import com.shiraku.homeworkfourth.model.dto.RegisterRequest;
import com.shiraku.homeworkfourth.model.entity.RefreshToken;
import com.shiraku.homeworkfourth.model.entity.RoleName;
import com.shiraku.homeworkfourth.model.entity.User;
import com.shiraku.homeworkfourth.repository.RefreshTokenRepository;
import com.shiraku.homeworkfourth.repository.UserRepository;
import com.shiraku.homeworkfourth.service.AuthService;
import com.shiraku.homeworkfourth.service.CustomUserDetailsService;
import com.shiraku.homeworkfourth.service.JwtService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
;
import java.util.Set;
import java.util.UUID;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @MockitoBean
    private UserRepository userRepository;
    @MockitoBean
    private RefreshTokenRepository refreshTokenRepository;
    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;
    @Autowired
    private JwtService jwtService;
    @MockitoBean
    private AuthService authService;
    private final ObjectMapper mapper = new ObjectMapper();


    @BeforeEach
    void setupMockUserDetails() {
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username("refreshUser")
                .password("123456")
                .authorities(new SimpleGrantedAuthority("ROLE_GUEST"))
                .build();

        when(customUserDetailsService.loadUserByUsername("refreshUser"))
                .thenReturn(userDetails);
    }


    @Test
    @DisplayName("POST /api/auth/register should return user")
    void testRegisterEndpoint() throws Exception {
        RegisterRequest request = new RegisterRequest("testuser", "password", "test@mail.com", Set.of("GUEST"));

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setLogin("testuser");
        user.setEmail("test@mail.com");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /api/auth/login should return access and set refresh cookie")
    void testLoginAndSetRefreshCookie() throws Exception {
        User user = new User();
        user.setLogin("loginUser");
        user.setEmail("login@example.com");
        user.setPassword(passwordEncoder.encode("secret"));
        user.setRoles(Set.of(RoleName.GUEST));
        userRepository.save(user);

        LoginRequest loginRequest = new LoginRequest("loginUser", "secret");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("User-Agent", "JUnit")
                        .content(mapper.writeValueAsString(loginRequest))
                        .with(req -> {
                            req.setRemoteAddr("127.0.0.1");
                            return req;
                        }))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /api/auth/refresh should return new access token from cookie")
    void testRefreshToken() throws Exception {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setLogin("refreshUser");
        user.setEmail("refresh@example.com");
        user.setPassword("123456");
        user.setRoles(Set.of(RoleName.GUEST));
        userRepository.saveAndFlush(user);

        String ip = "127.0.0.1";
        String userAgent = "JUnit";

        RefreshToken refreshToken = jwtService.createRefreshToken(user);
        String accessToken = jwtService.generateToken(user.getId(), user.getLogin(), user.getRoles(), ip, userAgent);

        MockHttpServletRequestBuilder requestBuilder = post("/api/auth/refresh")
                .header("Authorization", "Bearer " + accessToken)
                .header("User-Agent", userAgent)
                .cookie(new Cookie("refreshToken", refreshToken.getToken()))
                .contentType(MediaType.APPLICATION_JSON)
                .with(req -> {
                    req.setRemoteAddr(ip);
                    return req;
                });

        mockMvc.perform(requestBuilder)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").value(refreshToken.getToken()));
    }


    @Test
    @DisplayName("POST /api/auth/revoke should revoke tokens and return success")
    void testRevokeToken() throws Exception {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setLogin("refreshUser");
        user.setEmail("refresh@example.com");
        user.setPassword("123456");
        user.setRoles(Set.of(RoleName.GUEST));
        userRepository.saveAndFlush(user);

        String ip = "127.0.0.1";
        String userAgent = "JUnit";

        RefreshToken refreshToken = jwtService.createRefreshToken(user);
        String accessToken = jwtService.generateToken(user.getId(), user.getLogin(), user.getRoles(), ip, userAgent);

        MockHttpServletRequestBuilder requestBuilder = post("/api/auth/revoke")
                .header("Authorization", "Bearer " + accessToken)
                .cookie(new Cookie("refreshToken", refreshToken.getToken()))
                .contentType(MediaType.APPLICATION_JSON);

        mockMvc.perform(requestBuilder)
                .andExpect(status().isOk())
                .andExpect(content().string("Refresh token revoked successfully"));
    }

}
