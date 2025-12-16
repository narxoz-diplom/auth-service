package com.microservices.authservice.client;

import com.microservices.authservice.config.FeignConfig;
import com.microservices.authservice.dto.keycloak.KeycloakRole;
import com.microservices.authservice.dto.keycloak.KeycloakUser;
import com.microservices.authservice.dto.keycloak.PasswordRequest;
import feign.Response;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@FeignClient(
    name = "keycloak-admin-client",
    url = "${keycloak.url}",
    configuration = FeignConfig.class
)
public interface KeycloakAdminClient {

    @PostMapping(value = "/admin/realms/{realm}/users",
                 consumes = "application/json")
    Response createUser(
            @PathVariable("realm") String realm,
            @RequestBody KeycloakUser user
    );

    @PutMapping(value = "/admin/realms/{realm}/users/{userId}",
                consumes = "application/json")
    void updateUser(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestBody KeycloakUser user
    );

    @DeleteMapping("/admin/realms/{realm}/users/{userId}")
    void deleteUser(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId
    );

    @GetMapping("/admin/realms/{realm}/users/{userId}")
    KeycloakUser getUser(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId
    );

    @GetMapping("/admin/realms/{realm}/roles/{roleName}")
    KeycloakRole getRole(
            @PathVariable("realm") String realm,
            @PathVariable("roleName") String roleName
    );

    @PostMapping(value = "/admin/realms/{realm}/users/{userId}/role-mappings/realm",
                 consumes = "application/json")
    void assignRole(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestBody List<KeycloakRole> roles
    );

    @GetMapping("/admin/realms/{realm}/users/{userId}/role-mappings/realm")
    List<KeycloakRole> getUserRoles(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId
    );

    @PutMapping(value = "/admin/realms/{realm}/users/{userId}/reset-password",
                consumes = "application/json")
    void resetPassword(
            @PathVariable("realm") String realm,
            @PathVariable("userId") String userId,
            @RequestBody PasswordRequest passwordRequest
    );
}

