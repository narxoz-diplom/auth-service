package com.microservices.authservice.client;

import com.microservices.authservice.config.TokenClientFeignConfig;
import com.microservices.authservice.dto.keycloak.KeycloakTokenResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Map;

@FeignClient(
    name = "keycloak-token-client",
    url = "${keycloak.url}",
    configuration = TokenClientFeignConfig.class
)
public interface KeycloakTokenClient {

    @PostMapping(value = "/realms/{realm}/protocol/openid-connect/token",
                 consumes = "application/x-www-form-urlencoded")
    KeycloakTokenResponse getAdminToken(
            @PathVariable("realm") String realm,
            @RequestBody Map<String, Object> formParams
    );

    @PostMapping(value = "/realms/{realm}/protocol/openid-connect/token",
                 consumes = "application/x-www-form-urlencoded")
    KeycloakTokenResponse login(
            @PathVariable("realm") String realm,
            @RequestBody Map<String, Object> formParams
    );

    @PostMapping(value = "/realms/{realm}/protocol/openid-connect/token",
                 consumes = "application/x-www-form-urlencoded")
    KeycloakTokenResponse refreshToken(
            @PathVariable("realm") String realm,
            @RequestBody Map<String, Object> formParams
    );
}

