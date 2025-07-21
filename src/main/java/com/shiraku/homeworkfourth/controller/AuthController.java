package com.shiraku.homeworkfourth.controller;

import com.shiraku.homeworkfourth.model.dto.JwtTokenResponse;
import com.shiraku.homeworkfourth.model.dto.LoginRequest;
import com.shiraku.homeworkfourth.model.dto.RefreshRequest;
import com.shiraku.homeworkfourth.model.dto.RegisterRequest;
import com.shiraku.homeworkfourth.model.entity.User;
import com.shiraku.homeworkfourth.service.AuthService;
import jakarta.security.auth.message.AuthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<JwtTokenResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.authenticate(request.login(), request.password()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtTokenResponse> refresh(@RequestHeader("Authorization") String authHeader,
            @RequestBody RefreshRequest request) throws AuthException {
        String accessToken = authHeader.replace("Bearer ", "");
        authService.revokeAccessToken(accessToken);
        return ResponseEntity.ok(authService.refresh(request.refreshToken()));
    }

    @PostMapping("/revoke")
    public ResponseEntity<?> revokeToken(@RequestHeader("Authorization") String authHeader,
                                         @RequestBody RefreshRequest request) {
        try {
            String accessToken = authHeader.replace("Bearer ", "");
            authService.revokeRefreshToken(request.refreshToken(), accessToken);
            return ResponseEntity.ok("Refresh token revoked successfully");
        } catch (AuthException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

}
