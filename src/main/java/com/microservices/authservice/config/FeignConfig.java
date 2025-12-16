package com.microservices.authservice.config;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import feign.codec.ErrorDecoder;
import feign.Response;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
@Configuration
public class FeignConfig {

    private static final ThreadLocal<String> ADMIN_TOKEN = new ThreadLocal<>();

    public static void setAdminToken(String token) {
        ADMIN_TOKEN.set(token);
    }

    public static void clearAdminToken() {
        ADMIN_TOKEN.remove();
    }

    public ErrorDecoder errorDecoder() {
        return new KeycloakErrorDecoder();
    }

    @Bean
    public RequestInterceptor adminTokenInterceptor() {
        return template -> {
            String token = ADMIN_TOKEN.get();
            if (token != null) {
                template.header("Authorization", "Bearer " + token);
            }
        };
    }

    public static class KeycloakErrorDecoder implements ErrorDecoder {
        @Override
        public Exception decode(String methodKey, Response response) {
            String message = "Keycloak API error";
            try {
                if (response.body() != null) {
                    message = new String(response.body().asInputStream().readAllBytes(), StandardCharsets.UTF_8);
                }
            } catch (IOException e) {
                log.warn("Failed to read error response body", e);
            }
            
            log.error("Keycloak API error. Method: {}, Status: {}, Message: {}", 
                    methodKey, response.status(), message);
            
            return new RuntimeException(
                    String.format("Keycloak API error: %s (Status: %d)", message, response.status())
            );
        }
    }
}

