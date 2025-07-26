package com.shiraku.homeworkfourth.controller;

import com.shiraku.homeworkfourth.model.dto.*;
import com.shiraku.homeworkfourth.service.AuthService;
import com.shiraku.homeworkfourth.utils.CookieUtil;
import jakarta.security.auth.message.AuthException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.ok("user registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<JwtTokenResponse> login(HttpServletRequest httpRequest, @RequestBody LoginRequest request) {
        System.out.printf("Login request: %s\n", request);

        String ip = httpRequest.getRemoteAddr();
        String userAgent = httpRequest.getHeader("User-Agent");
        JwtTokenServiceResponse tokens = authService.authenticate(request.login(), request.password(), ip, userAgent);

        ResponseCookie cookie = ResponseCookie.from("refreshToken", tokens.refreshToken())
                .httpOnly(true)
                .secure(false)
                .path("/api/auth/refresh")
                .maxAge(Duration.ofDays(7))
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(JwtTokenResponse.fromJwtTokenServiceResponse(tokens));
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtTokenResponse> refresh(@RequestHeader("Authorization") String authHeader,
                                                    HttpServletRequest servletRequest) throws AuthException {
        String accessToken = authHeader.replace("Bearer ", "");
        String ip = servletRequest.getRemoteAddr();
        String userAgent = servletRequest.getHeader("User-Agent");

        String refreshToken = CookieUtil.extractCookie(servletRequest.getCookies(), "refreshToken");

        authService.revokeAccessToken(accessToken);
        JwtTokenServiceResponse response = authService.refresh(refreshToken, ip, userAgent);

        return ResponseEntity.ok(JwtTokenResponse.fromJwtTokenServiceResponse(response));
    }

    @PostMapping("/revoke")
    public ResponseEntity<?> revokeToken(@RequestHeader("Authorization") String authHeader,
                                         HttpServletRequest servletRequest) {
        try {
            String accessToken = authHeader.replace("Bearer ", "");
            String refreshToken = CookieUtil.extractCookie(servletRequest.getCookies(), "refreshToken");

            authService.revokeRefreshToken(refreshToken, accessToken);
            return ResponseEntity.ok("Refresh token revoked successfully");
        } catch (AuthException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }


}
