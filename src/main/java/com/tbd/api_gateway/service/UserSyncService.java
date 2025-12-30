package com.tbd.api_gateway.service;

import com.tbd.api_gateway.exception.UserSyncException;
import com.tbd.api_gateway.model.UserSyncRequest;
import com.tbd.api_gateway.model.UserSyncResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserSyncService {

    private final WebClient userWebClient;

    @Value("${app.api.endpoint.secret}")
    private String apiSecret;

    public Mono<UserSyncResponse> syncUser(OAuth2User principal) {

        UserSyncRequest userSyncRequest = new UserSyncRequest(
                principal.getAttribute("email"),
                principal.getAttribute("sub"),
                principal.getAttribute("name"),
                principal.getAttribute("picture"),
                principal.getAttribute("email_verified")
        );

        return userWebClient
                .post()
                .uri("/api/internal/users/sync")
                .bodyValue(userSyncRequest)
                .header("X-Internal-Secret", apiSecret)
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                        clientResponse.bodyToMono(String.class) // Read the error body from User Service
                                .flatMap(errorBody -> {
                                    log.error("User Service Error: {} - Body: {}", clientResponse.statusCode(), errorBody);
                                    return Mono.error(new UserSyncException("Sync failed: " + errorBody));
                                })
                )
                .bodyToMono(UserSyncResponse.class)
                .timeout(Duration.ofSeconds(5))
                .retryWhen(Retry.fixedDelay(3, Duration.ofSeconds(2))
                        // Risk Control: Don't retry if it's a 4xx error (client error)
                        .filter(throwable -> !(throwable instanceof WebClientResponseException.BadRequest))
                );
    }

}
