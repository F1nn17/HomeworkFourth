package com.shiraku.homeworkfourth.service;

import com.shiraku.homeworkfourth.model.dto.JwtTokenResponse;
import com.shiraku.homeworkfourth.model.dto.RegisterRequest;
import com.shiraku.homeworkfourth.model.entity.RefreshToken;
import com.shiraku.homeworkfourth.model.entity.RoleName;
import com.shiraku.homeworkfourth.model.entity.User;
import com.shiraku.homeworkfourth.repository.UserRepository;
import jakarta.security.auth.message.AuthException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final RefreshTokenService refreshTokenService;

    private final TokenBlacklistService tokenBlacklistService;

    private final JwtService jwtService;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, RefreshTokenService refreshTokenService, TokenBlacklistService tokenBlacklistService, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.jwtService = jwtService;
    }

    @Transactional
    public User register(RegisterRequest request){
        User user = new User();
        user.setLogin(request.login());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));

        Set<RoleName> roleNames = request.roles()
                .stream()
                .map(String::toUpperCase)
                .map(RoleName::valueOf)
                .collect(Collectors.toSet());

        user.setRoles(roleNames);

        return userRepository.save(user);
    }

    public JwtTokenResponse authenticate(String login, String rawPassword) {
        User user = userRepository.findByLogin(login)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        String accessToken = jwtService.generateToken(user.getId(), user.getLogin(), user.getRoles());
        RefreshToken refreshToken = refreshTokenService.createToken(user);

        log.info("User authenticated: {}", user);

        return new JwtTokenResponse(accessToken, refreshToken.getToken());
    }

    public JwtTokenResponse refresh(String refreshTokenStr) throws AuthException {
        RefreshToken refreshToken = refreshTokenService.validate(refreshTokenStr);
        User user = refreshToken.getUser();
        String newAccessToken = jwtService.generateToken(user.getId(), user.getLogin(), user.getRoles());
        return new JwtTokenResponse(newAccessToken, refreshTokenStr);
    }

    public void revokeAccessToken(String accessToken) {
        Instant expiry = jwtService.extractExpiration(accessToken);
        tokenBlacklistService.blacklist(accessToken, expiry);
    }

    public void revokeRefreshToken(String refreshToken,  String accessToken) throws AuthException {
        refreshTokenService.revoke(refreshToken);
        revokeAccessToken(accessToken);
    }



}
