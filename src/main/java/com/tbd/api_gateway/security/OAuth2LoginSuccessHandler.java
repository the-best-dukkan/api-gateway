package com.tbd.api_gateway.security;

import com.tbd.api_gateway.config.JWTConfig;
import com.tbd.api_gateway.service.UserSyncService;
import com.tbd.api_gateway.util.TbdJWTUtil;
import com.tbd.api_gateway.util.Util;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler implements ServerAuthenticationSuccessHandler {

    private final JWTConfig jwtConfig;
    private final UserSyncService userSyncService;

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {

        ServerWebExchange exchange = webFilterExchange.getExchange();
        OAuth2User principal = (OAuth2User) authentication.getPrincipal();

        return userSyncService.syncUser(principal)
                .flatMap(userInternal -> {

                    String accessToken = TbdJWTUtil.generateAccessToken(jwtConfig, userInternal);
                    String refreshToken = TbdJWTUtil.generateRefreshToken(jwtConfig, userInternal);

                    // 1. Set Access token and Refresh Token as an HttpOnly Cookie
                    ResponseCookie accessCookie = Util.getAccessTokenCookie(jwtConfig, accessToken);
                    ResponseCookie refreshCookie = Util.getRefreshTokenCookie(jwtConfig, refreshToken);

                    exchange.getResponse().addCookie(accessCookie);
                    exchange.getResponse().addCookie(refreshCookie);

                    String redirectUrl = "http://localhost:4200/login-success";

                    exchange.getResponse().setStatusCode(HttpStatus.FOUND);
                    exchange.getResponse().getHeaders().setLocation(URI.create(redirectUrl));

                    return exchange.getResponse().setComplete();
                })
                .onErrorResume(ex -> {
                    log.error("Sync failed after all service-level retries: {}", ex.getMessage());
                    return redirectToErrorPage(exchange);
                });
    }

    private Mono<Void> redirectToErrorPage(ServerWebExchange exchange) {

        // Better Way: Redirect to an Error Page on your Angular app
        String errorRedirectUrl = "http://localhost:4200/login-error?reason=sync_failure";

        exchange.getResponse().setStatusCode(HttpStatus.FOUND);
        exchange.getResponse().getHeaders().setLocation(URI.create(errorRedirectUrl));
        return exchange.getResponse().setComplete();
    }
}
