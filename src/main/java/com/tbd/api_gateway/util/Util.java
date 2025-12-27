package com.tbd.api_gateway.util;

import com.tbd.api_gateway.config.JWTConfig;
import com.tbd.api_gateway.constant.Constants;
import org.springframework.http.ResponseCookie;

import java.time.Duration;

public class Util {

    private Util() {}

    public static ResponseCookie getAccessTokenCookie(JWTConfig jwtConfig, String accessToken) {
        return ResponseCookie.from(Constants.ACCESS_TOKEN, accessToken)
                .httpOnly(true)
                .secure(true) // Only sent over HTTPS
                .path("/")
                .maxAge(Duration.ofDays(jwtConfig.getAccessTokenExpiryInMinutes()))
                .sameSite("Strict")
                .build();
    }

    public static ResponseCookie getRefreshTokenCookie(JWTConfig jwtConfig, String refreshToken) {
        return ResponseCookie.from(Constants.REFRESH_TOKEN, refreshToken)
                .httpOnly(true)
                .secure(true) // Only sent over HTTPS
                .path("/")
                .maxAge(Duration.ofDays(jwtConfig.getRefreshTokenExpiryInDays()))
                .sameSite("Strict")
                .build();
    }
}
