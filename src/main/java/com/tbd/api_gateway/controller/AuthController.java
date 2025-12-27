package com.tbd.api_gateway.controller;

import com.tbd.api_gateway.config.JWTConfig;
import com.tbd.api_gateway.constant.Constants;
import com.tbd.api_gateway.service.RefreshTokenService;
import com.tbd.api_gateway.util.Util;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/tbd/api/auth")
public class AuthController {

    private final JWTConfig jwtConfig;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/refresh")
    public Mono<ResponseEntity<Map<String, String>>> refreshToken(ServerWebExchange exchange) {

        HttpCookie refreshCookie = exchange.getRequest().getCookies().getFirst(Constants.REFRESH_TOKEN);

        Map<String, String> response = new HashMap<>();

        if (refreshCookie == null) {
            response.put("response", "No refresh token found in cookie");
            return Mono.just(new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED));
        }

        String refreshToken = refreshCookie.getValue();

        return refreshTokenService.refreshToken(refreshToken)
                .flatMap(tokenPair -> {

                    ResponseCookie accessCookie = Util.getAccessTokenCookie(jwtConfig, tokenPair.getAccessToken());
                    ResponseCookie newRefreshCookie = Util.getRefreshTokenCookie(jwtConfig, tokenPair.getRefreshToken());

                    exchange.getResponse().addCookie(accessCookie);
                    exchange.getResponse().addCookie(newRefreshCookie);

                    return Mono.just(new ResponseEntity<>(response, HttpStatus.OK));
                })
                .onErrorResume(ex -> {

                    response.put("response", ex.getMessage());
                    return Mono.just(new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED));
                });
    }
}
