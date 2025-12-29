package com.tbd.api_gateway.service;

import com.tbd.api_gateway.config.JWTConfig;
import com.tbd.api_gateway.constant.Constants;
import com.tbd.api_gateway.model.RefreshTokenMetadata;
import com.tbd.api_gateway.model.TokenPair;
import com.tbd.api_gateway.model.UserSyncResponse;
import com.tbd.api_gateway.util.TbdJWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final ReactiveRedisTemplate<String, Object> reactiveRedisTemplate;
    private final JWTConfig jwtConfig;

    public Mono<TokenPair> refreshToken(String refreshToken) {

        RefreshTokenMetadata refreshTokenMetadata;

        try {
            refreshTokenMetadata = TbdJWTUtil.validateRefreshTokenAndGetMetadata(jwtConfig, refreshToken);
        } catch (ExpiredJwtException e) {
            return Mono.error(new SecurityException("Token has expired"));
        } catch (JwtException e) {
            return Mono.error(new SecurityException("Invalid token"));
        }

        if (refreshTokenMetadata.getTokenType().equals(Constants.ACCESS_TOKEN)) {
            return Mono.error(new SecurityException("Invalid token"));
        }

        Duration ttl = Duration.between(Instant.now(), refreshTokenMetadata.getExpiration().toInstant());

        return reactiveRedisTemplate.opsForValue()
                .setIfAbsent("auth:refresh:used:" + refreshTokenMetadata.getJti(), refreshTokenMetadata.getSub(), ttl)
                .flatMap(firstUse -> {
                    if (!firstUse) {
                        return Mono.error(new SecurityException("Refresh token replay"));
                    } else {

                        UserSyncResponse userSyncResponse = new UserSyncResponse(
                                refreshTokenMetadata.getEmail(),
                                refreshTokenMetadata.getSub(),
                                null, false, refreshTokenMetadata.getRoles()
                        );

                        return Mono.just(
                                new TokenPair(
                                        TbdJWTUtil.generateAccessToken(jwtConfig, userSyncResponse),
                                        TbdJWTUtil.generateRefreshToken(jwtConfig, userSyncResponse)
                                )
                        );
                    }
                });
    }
}
