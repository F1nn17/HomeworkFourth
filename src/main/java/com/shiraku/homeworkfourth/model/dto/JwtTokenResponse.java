package com.shiraku.homeworkfourth.model.dto;

public record JwtTokenResponse(
        String accessToken
) {
    public static JwtTokenResponse fromJwtTokenServiceResponse(JwtTokenServiceResponse token) {
        return new JwtTokenResponse(token.accessToken());
    }
}
