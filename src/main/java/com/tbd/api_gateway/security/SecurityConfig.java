package com.tbd.api_gateway.security;

import com.tbd.api_gateway.config.JWTConfig;
import com.tbd.api_gateway.security.jwt.JjwtReactiveJwtDecoder;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JWTConfig jwtConfig;

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http, OAuth2LoginSuccessHandler oauth2LoginSuccessHandler) {

        return http
                .cors(ServerHttpSecurity.CorsSpec::disable)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                // Set the Session Management to STATELESS
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/login/**").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2.authenticationSuccessHandler(oauth2LoginSuccessHandler))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                )
                .build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {

        return new JjwtReactiveJwtDecoder(jwtConfig);
    }
}
