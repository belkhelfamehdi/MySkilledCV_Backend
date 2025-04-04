package com.sparky.user_service.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "spring.application.security.jwt")
@Getter
@Setter
public class JwtConfig {
    private String secretKey;
    private long expirationTime;
}