package com.tbd.api_gateway.security.jwt;

import com.tbd.api_gateway.config.JWTConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@RequiredArgsConstructor
public class JjwtReactiveJwtDecoder implements ReactiveJwtDecoder {

    private final JWTConfig jwtConfig;

    @Override
    public Mono<Jwt> decode(String token) throws JwtException {
        return Mono.fromCallable(() -> {
            SecretKey key = Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8));

            // Use JJWT to parse the token
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .requireIssuer(jwtConfig.getIssuer())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // Convert JJWT Claims to Spring Security JWT object
            return new Jwt(
                    token,
                    claims.getIssuedAt().toInstant(),
                    claims.getExpiration().toInstant(),
                    Map.of("alg", "HS256", "typ", "JWT"), // Header
                    claims // Payload
            );
        }).onErrorMap(e -> new JwtException("Invalid token: " + e.getMessage(), e));
    }
}
