package com.tbd.api_gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app.jwt")
@Data
public class JWTConfig {

    private String secret;
    private String issuer;
    private Integer accessTokenExpiryInMinutes;
    private Integer refreshTokenExpiryInDays;
}
