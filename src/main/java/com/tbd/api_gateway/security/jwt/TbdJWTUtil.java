package com.tbd.api_gateway.security.jwt;

import com.tbd.api_gateway.config.JWTConfig;
import com.tbd.api_gateway.model.UserSyncResponse;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class TbdJWTUtil {

    private TbdJWTUtil() {
    }

    public static String generateAccessToken(JWTConfig jwtConfig, UserSyncResponse userSyncResponse) {

        Instant now = Instant.now();

        Map<String, Object> claims = new HashMap<>();
        claims.put("email", userSyncResponse.email());
        claims.put("roles", userSyncResponse.roles());

        return Jwts.builder()
                .issuer(jwtConfig.getIssuer())
                .subject(userSyncResponse.sub())
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(Duration.ofMinutes(jwtConfig.getAccessTokenExpiryInMinutes()))))
                .signWith(Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public static String generateRefreshToken(JWTConfig jwtConfig, String sub) {

        Instant now = Instant.now();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(jwtConfig.getIssuer())
                .subject(sub)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(Duration.ofDays(jwtConfig.getRefreshTokenExpiryInDays()))))
                .signWith(Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8)))
                .compact();
    }
}
