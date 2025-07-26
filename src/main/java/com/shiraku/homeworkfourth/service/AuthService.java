package com.shiraku.homeworkfourth.service;


import com.shiraku.homeworkfourth.model.dto.JwtTokenServiceResponse;
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

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Transactional
    public void register(RegisterRequest request){
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setLogin(request.login());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));

        Set<RoleName> roleNames = request.roles()
                .stream()
                .map(String::toUpperCase)
                .map(RoleName::valueOf)
                .collect(Collectors.toSet());

        user.setRoles(roleNames);

        userRepository.save(user);
    }

    public JwtTokenServiceResponse authenticate(String login, String rawPassword, String ip, String userAgent) {
        User user = userRepository.findByLogin(login)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        String accessToken = jwtService.generateToken(
                user.getId(),
                user.getLogin(),
                user.getRoles(),
                ip,
                userAgent
        );

        RefreshToken refreshToken = jwtService.createRefreshToken(user);

        return new JwtTokenServiceResponse(accessToken, refreshToken.getToken());
    }

    @Transactional
    public JwtTokenServiceResponse refresh(String refreshTokenStr, String ip, String userAgent) throws AuthException {
        RefreshToken refreshToken = jwtService.validate(refreshTokenStr);
        User user = refreshToken.getUser();

        String newAccessToken = jwtService.generateToken(
                user.getId(),
                user.getLogin(),
                user.getRoles(),
                ip,
                userAgent
        );

        return new JwtTokenServiceResponse(newAccessToken, refreshTokenStr);
    }

    public void revokeAccessToken(String accessToken) {
        jwtService.revokeAccessToken(accessToken);
    }

    public void revokeRefreshToken(String refreshToken,  String accessToken) throws AuthException {
        jwtService.revokeRefreshToken(refreshToken);
        revokeAccessToken(accessToken);
    }
}
