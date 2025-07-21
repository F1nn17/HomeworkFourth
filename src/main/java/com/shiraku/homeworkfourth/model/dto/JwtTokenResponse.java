package com.shiraku.homeworkfourth.model.dto;

public record JwtTokenResponse(
        String accessToken,
        String refreshToken
) {
}
