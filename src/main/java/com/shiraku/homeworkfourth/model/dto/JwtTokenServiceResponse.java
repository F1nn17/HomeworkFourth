package com.shiraku.homeworkfourth.model.dto;

public record JwtTokenServiceResponse(
        String accessToken,
        String refreshToken
) {
}
