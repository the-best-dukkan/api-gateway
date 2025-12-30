package com.tbd.api_gateway.security;

import com.tbd.api_gateway.config.JWTConfig;
import com.tbd.api_gateway.security.jwt.JjwtReactiveJwtDecoder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final JWTConfig jwtConfig;

    @Value("${spring.application.name}")
    private String appName;

    @Bean
    @Order(1)
    public SecurityWebFilterChain apiSecurity(ServerHttpSecurity http) {

        return http
                .securityMatcher(
                        ServerWebExchangeMatchers.pathMatchers("/tbd/api/**")
                )
                .cors(ServerHttpSecurity.CorsSpec::disable)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                // Set the Session Management to STATELESS
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/login/**", "/tbd/" + appName + "/actuator/**", "/tbd/auth/refresh").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint((exchange, ex) -> {
                            log.error("JWT Authentication EntryPoint");
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        })
                )
                .build();
    }

    @Bean
    @Order(2)
    public SecurityWebFilterChain loginSecurity(ServerHttpSecurity http, OAuth2LoginSuccessHandler oauth2LoginSuccessHandler) {

        return http
                .securityMatcher(
                        ServerWebExchangeMatchers.pathMatchers("/**")
                )
                .cors(ServerHttpSecurity.CorsSpec::disable)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                // Set the Session Management to STATELESS
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(exchanges -> exchanges
                        .anyExchange().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2.authenticationSuccessHandler(oauth2LoginSuccessHandler))
                .build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {

        return new JjwtReactiveJwtDecoder(jwtConfig);
    }
}
