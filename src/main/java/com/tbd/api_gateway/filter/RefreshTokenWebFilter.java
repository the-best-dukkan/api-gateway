package com.tbd.api_gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tbd.api_gateway.config.JWTConfig;
import com.tbd.api_gateway.constant.Constants;
import com.tbd.api_gateway.service.RefreshTokenService;
import com.tbd.api_gateway.util.Util;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Component
@Order(-1000000)
@RequiredArgsConstructor
public class RefreshTokenWebFilter implements WebFilter {

    private final RefreshTokenService refreshTokenService;
    private final JWTConfig jwtConfig;
    private final ObjectMapper objectMapper;
    private final ReactiveRedisTemplate<String, String> redisTemplate;

    private static final String REFRESH_PATH = "/tbd/auth/refresh";
    private static final int BURST = 2;
    private static final int REFILL_PER_SECOND = 1;

    private static final String LUA_TOKEN_BUCKET = """
                local key = KEYS[1]
                local capacity = tonumber(ARGV[1])
                local refill_rate = tonumber(ARGV[2])
                local now = tonumber(ARGV[3])
            
                local data = redis.call("HMGET", key, "tokens", "timestamp")
                local tokens = tonumber(data[1]) or capacity
                local last_ts = tonumber(data[2]) or now
            
                local delta = math.max(0, now - last_ts)
                tokens = math.min(capacity, tokens + delta * refill_rate)
            
                if tokens < 1 then
                  return 0
                end
            
                redis.call("HMSET", key, "tokens", tokens - 1, "timestamp", now)
                redis.call("EXPIRE", key, 60)
                return 1
            """;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();

        // Only intercept refresh endpoint
        if (!request.getPath().value().equals(REFRESH_PATH)
                || request.getMethod() != HttpMethod.POST) {
            return chain.filter(exchange);
        }

        HttpCookie refreshCookie =
                request.getCookies().getFirst(Constants.REFRESH_TOKEN);

        if (refreshCookie == null) {
            return unauthorized(exchange, "No refresh token found");
        }

        String refreshToken = refreshCookie.getValue();

        String rateKey = getRefreshRateLimiterKey(exchange);

        return isAllowed(rateKey)
                .flatMap(allowed -> {
                    if (!allowed) {
                        return tooManyRequests(exchange);
                    }

                    return refreshTokenService.refreshToken(refreshToken)
                            .flatMap(tokenPair -> {
                                exchange.getResponse().addCookie(
                                        Util.getAccessTokenCookie(jwtConfig, tokenPair.getAccessToken())
                                );
                                exchange.getResponse().addCookie(
                                        Util.getRefreshTokenCookie(jwtConfig, tokenPair.getRefreshToken())
                                );
                                return ok(exchange);
                            });
                })
                .onErrorResume(ex -> unauthorized(exchange, ex.getMessage()));
    }

    private String getRefreshRateLimiterKey(ServerWebExchange exchange) {

        String ua = exchange.getRequest().getHeaders().getFirst("User-Agent");
        return "rate:refresh:ipua:" + sha256(Util.resolveClientIp(exchange) + ua);
    }

    /* ---------------- Rate Limiting ---------------- */

    private Mono<Boolean> isAllowed(String key) {
        long now = System.currentTimeMillis() / 1000;

        return redisTemplate.execute(
                new DefaultRedisScript<>(LUA_TOKEN_BUCKET, Long.class),
                List.of(key),
                String.valueOf(BURST),
                String.valueOf(REFILL_PER_SECOND),
                String.valueOf(now)
        ).next().map(v -> v == 1);
    }

    /* ---------------- Responses ---------------- */

    private Mono<Void> ok(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.OK);
        return write(exchange, Map.of("status", "success"));
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String msg) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return write(exchange, Map.of("error", msg));
    }

    private Mono<Void> tooManyRequests(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        return write(exchange, Map.of("error", "Too many refresh attempts"));
    }

    private Mono<Void> write(ServerWebExchange exchange, Map<String, String> body) {
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(body);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        } catch (Exception e) {
            return Mono.error(e);
        }
    }

    private String sha256(String value) {
        return DigestUtils.sha256Hex(value);
    }
}
