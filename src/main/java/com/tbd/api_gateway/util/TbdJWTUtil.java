package com.tbd.api_gateway.util;

import com.tbd.api_gateway.config.JWTConfig;
import com.tbd.api_gateway.constant.Constants;
import com.tbd.api_gateway.model.RefreshTokenMetadata;
import com.tbd.api_gateway.model.TbdRole;
import com.tbd.api_gateway.model.UserSyncResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class TbdJWTUtil {

    private TbdJWTUtil() {
    }

    private static SecretKey getSigningKey(String secret) {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private static HashMap<String, Object> getCommonClaims(UserSyncResponse userSyncResponse) {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put(Constants.EMAIL, userSyncResponse.email());
        claims.put(Constants.ROLES, userSyncResponse.roles().stream().map(TbdRole::name).toList());
        return claims;
    }

    public static String generateAccessToken(JWTConfig jwtConfig, UserSyncResponse userSyncResponse) {

        SecretKey key = getSigningKey(jwtConfig.getSecret());

        Map<String, Object> claims = getCommonClaims(userSyncResponse);
        claims.put(Constants.TOKEN_TYPE, Constants.ACCESS_TOKEN);

        Instant now = Instant.now();

        return Jwts.builder()
                .issuer(jwtConfig.getIssuer())
                .subject(userSyncResponse.sub())
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(Instant.now().plus(Duration.ofMinutes(jwtConfig.getAccessTokenExpiryInMinutes()))))
                .signWith(key)
                .compact();
    }

    public static String generateRefreshToken(JWTConfig jwtConfig, UserSyncResponse userSyncResponse) {

        SecretKey key = getSigningKey(jwtConfig.getSecret());

        Map<String, Object> claims = getCommonClaims(userSyncResponse);
        claims.put(Constants.TOKEN_TYPE, Constants.REFRESH_TOKEN);

        Instant now = Instant.now();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(jwtConfig.getIssuer())
                .subject(userSyncResponse.sub())
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(Instant.now().plus(Duration.ofDays(jwtConfig.getRefreshTokenExpiryInDays()))))
                .signWith(key)
                .compact();
    }

    public static RefreshTokenMetadata validateRefreshTokenAndGetMetadata(JWTConfig jwtConfig, String refreshToken) {

        // 1. Parse and Validate (Throws exception if expired or signature invalid)
        Claims claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8))) // The same signing key used to generate it
                .requireIssuer(jwtConfig.getIssuer())
                .build()
                .parseSignedClaims(refreshToken)
                .getPayload();

        List<String> roles = claims.get(Constants.ROLES, List.class);

        return new RefreshTokenMetadata(
                claims.getSubject(),
                claims.get(Constants.EMAIL, String.class),
                roles.stream().map(TbdRole::new).collect(Collectors.toSet()),
                claims.getId(),
                claims.getExpiration(),
                claims.get(Constants.TOKEN_TYPE, String.class)
        );
    }
}
