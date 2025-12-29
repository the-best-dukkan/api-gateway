package com.tbd.api_gateway.rate_limit.key_resolvers;

import com.tbd.api_gateway.constant.Constants;
import com.tbd.api_gateway.util.Util;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Primary
@Component("commonApiKeyResolver")
public class CommonAPIKeyResolver implements KeyResolver {

    @Override
    public Mono<String> resolve(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(Constants.X_USER_ID))
                .defaultIfEmpty(Util.resolveClientIp(exchange));
    }
}
