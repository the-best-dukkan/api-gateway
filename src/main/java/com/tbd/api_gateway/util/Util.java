package com.tbd.api_gateway.util;

import com.tbd.api_gateway.config.JWTConfig;
import com.tbd.api_gateway.constant.Constants;
import org.springframework.cloud.gateway.support.ipresolver.XForwardedRemoteAddressResolver;
import org.springframework.http.ResponseCookie;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetSocketAddress;
import java.time.Duration;

public class Util {

    private Util() {}

    public static ResponseCookie getAccessTokenCookie(JWTConfig jwtConfig, String accessToken) {
        return ResponseCookie.from(Constants.ACCESS_TOKEN, accessToken)
                .httpOnly(true)
                .secure(true) // Only sent over HTTPS
                .path("/")
                .maxAge(Duration.ofMinutes(jwtConfig.getAccessTokenExpiryInMinutes()))
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

    public static String resolveClientIp(ServerWebExchange exchange) {

        // maxTrustedIndex(1) means: "I trust 1 proxy (my Load Balancer).
        // Take the IP that the Load Balancer saw."
        XForwardedRemoteAddressResolver resolver = XForwardedRemoteAddressResolver.maxTrustedIndex(1);
        InetSocketAddress address = resolver.resolve(exchange);

        return (address != null && address.getAddress() != null)
                ? address.getAddress().getHostAddress()
                : "unknown";
    }

}
