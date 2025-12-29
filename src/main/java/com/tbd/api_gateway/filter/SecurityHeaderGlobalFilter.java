package com.tbd.api_gateway.filter;

import com.tbd.api_gateway.constant.Constants;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Order(value = -100)
public class SecurityHeaderGlobalFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .flatMap(auth -> {

                    String userId = auth.getName();

                    // Mutate the request to add the header for the KeyResolver and Microservices
                    ServerWebExchange mutatedExchange = exchange.mutate()
                            .request(r -> r.header(Constants.X_USER_ID, userId))
                            .build();

                    return chain.filter(mutatedExchange);
                });
    }
}
