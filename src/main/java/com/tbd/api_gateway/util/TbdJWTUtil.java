package com.tbd.api_gateway.util;

import com.tbd.api_gateway.config.JWTConfig;
import com.tbd.api_gateway.constant.Constants;
import com.tbd.api_gateway.model.RefreshTokenMetadata;
import com.tbd.api_gateway.model.TbdRole;
import com.tbd.api_gateway.model.UserSyncResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class TbdJWTUtil {

    private TbdJWTUtil() {
    }

    public static String generateAccessToken(JWTConfig jwtConfig, UserSyncResponse userSyncResponse) {

        JwtBuilder jwtBuilder = getJWTBuilderWithCommonValues(jwtConfig, userSyncResponse, false);

        return jwtBuilder
                .signWith(Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public static String generateRefreshToken(JWTConfig jwtConfig, UserSyncResponse userSyncResponse) {

        JwtBuilder jwtBuilder = getJWTBuilderWithCommonValues(jwtConfig, userSyncResponse, true);

        return jwtBuilder
                .id(UUID.randomUUID().toString())
                .signWith(Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public static RefreshTokenMetadata validateRefreshTokenAndGetMetadata(JWTConfig jwtConfig, String refreshToken) {

        // 1. Parse and Validate (Throws exception if expired or signature invalid)
        Claims claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8))) // The same signing key used to generate it
                .build()
                .parseSignedClaims(refreshToken)
                .getPayload();

        List<String> roles = claims.get(Constants.ROLES, List.class);

        return new RefreshTokenMetadata(
                claims.getSubject(),
                claims.get(Constants.EMAIL, String.class),
                roles.stream().map(TbdRole::new).collect(Collectors.toSet()),
                claims.getId(),
                claims.getExpiration()
        );
    }

    private static JwtBuilder getJWTBuilderWithCommonValues(JWTConfig jwtConfig, UserSyncResponse userSyncResponse, boolean isRefreshToken) {

        Instant now = Instant.now();

        Map<String, Object> claims = new HashMap<>();
        claims.put(Constants.EMAIL, userSyncResponse.email());
        claims.put(Constants.ROLES, userSyncResponse.roles().stream().map(TbdRole::name).toList());

        Duration durationToAdd;

        if (isRefreshToken) {
            durationToAdd = Duration.ofDays(jwtConfig.getRefreshTokenExpiryInDays());
        } else {
            durationToAdd = Duration.ofMinutes(jwtConfig.getAccessTokenExpiryInMinutes());
        }

        return Jwts.builder()
                .issuer(jwtConfig.getIssuer())
                .subject(userSyncResponse.sub())
                .issuedAt(Date.from(now))
                .claims(claims)
                .expiration(Date.from(now.plus(durationToAdd)));
    }
}
