package com.microservices.authservice.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.microservices.authservice.client.KeycloakAdminClient;
import com.microservices.authservice.client.KeycloakTokenClient;
import com.microservices.authservice.config.FeignConfig;
import com.microservices.authservice.dto.RegistrationRequest;
import com.microservices.authservice.dto.UpdateUserRequest;
import com.microservices.authservice.dto.UserInfo;
import com.microservices.authservice.dto.keycloak.KeycloakRole;
import com.microservices.authservice.dto.keycloak.KeycloakTokenResponse;
import com.microservices.authservice.dto.keycloak.KeycloakUser;
import com.microservices.authservice.dto.keycloak.PasswordRequest;
import feign.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakService {

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.admin.client-id}")
    private String adminClientId;

    @Value("${keycloak.admin.client-secret}")
    private String adminClientSecret;

    @Value("${keycloak.admin.username}")
    private String adminUsername;

    @Value("${keycloak.admin.password}")
    private String adminPassword;

    private final KeycloakTokenClient tokenClient;
    private final KeycloakAdminClient adminClient;
    private final ObjectMapper objectMapper;


    public String getAdminToken() {
        try {
            Map<String, Object> formParams = new HashMap<>();
            formParams.put("grant_type", "client_credentials");
            formParams.put("client_id", adminClientId);
            formParams.put("client_secret", adminClientSecret);

            KeycloakTokenResponse response = tokenClient.getAdminToken("master", formParams);

            if (response != null && response.getAccessToken() != null) {
                log.info("Successfully obtained admin token");
                return response.getAccessToken();
            } else {
                log.error("Failed to get admin token. Response is null or missing access_token");
                throw new RuntimeException("Failed to get admin token");
            }
        } catch (Exception e) {
            log.error("Error getting admin token", e);
            throw new RuntimeException("Error getting admin token: " + e.getMessage(), e);
        }
    }

    public String createUser(RegistrationRequest registrationRequest) {
        String adminToken = getAdminToken();
        if (adminToken == null) {
            throw new RuntimeException("Failed to authenticate with Keycloak admin");
        }

        try {
            KeycloakUser keycloakUser = KeycloakUser.builder()
                    .username(registrationRequest.getUsername())
                    .email(registrationRequest.getEmail())
                    .firstName(registrationRequest.getFirstName())
                    .lastName(registrationRequest.getLastName())
                    .enabled(true)
                    .emailVerified(true)
                    .build();

            FeignConfig.setAdminToken(adminToken);
            try {
                Response response = adminClient.createUser(realm, keycloakUser);

                String userId = null;
                if (response.status() == 201) {
                    String location = response.headers().get("Location").stream()
                            .findFirst()
                            .orElse(null);
                    if (location != null) {
                        userId = location.substring(location.lastIndexOf("/") + 1);
                    }
                } else if (response.status() == 409) {
                    log.warn("User already exists: {}", registrationRequest.getUsername());
                    throw new IllegalArgumentException("User with this username or email already exists");
                } else {
                    log.error("Failed to create user. Status: {}", response.status());
                    throw new RuntimeException("Failed to create user");
                }

                if (userId != null) {
                    PasswordRequest passwordRequest = PasswordRequest.builder()
                            .type("password")
                            .value(registrationRequest.getPassword())
                            .temporary(false)
                            .build();

                    try {
                        adminClient.resetPassword(realm, userId, passwordRequest);
                        log.info("Password set successfully for user: {}", registrationRequest.getUsername());
                        return userId;
                    } catch (Exception e) {
                        log.error("Failed to set password", e);
                        deleteUser(userId);
                        throw new RuntimeException("Failed to set password", e);
                    }
                }
            } finally {
                FeignConfig.clearAdminToken();
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error creating user", e);
            throw new RuntimeException("Error creating user: " + e.getMessage(), e);
        }
        return null;
    }

    public boolean assignRole(String userId, String roleName) {
        String adminToken = getAdminToken();
        if (adminToken == null) {
            return false;
        }

        try {
            log.info("Attempting to assign role '{}' to user '{}'", roleName, userId);

            FeignConfig.setAdminToken(adminToken);
            try {
                KeycloakRole role = adminClient.getRole(realm, roleName);
                if (role == null) {
                    log.error("Role '{}' not found in realm '{}'", roleName, realm);
                    return false;
                }

                log.debug("Retrieved role: {}", role);

                adminClient.assignRole(realm, userId, List.of(role));
                log.info("Role '{}' successfully assigned to user '{}'", roleName, userId);
                return verifyRoleAssignment(userId, roleName, adminToken);
            } catch (Exception e) {
                log.error("Failed to assign role '{}' to user '{}'", roleName, userId, e);
                return false;
            } finally {
                FeignConfig.clearAdminToken();
            }
        } catch (Exception e) {
            log.error("Exception while assigning role '{}' to user '{}': {}", roleName, userId, e.getMessage(), e);
            return false;
        }
    }

    public boolean roleExists(String roleName) {
        String adminToken = getAdminToken();
        if (adminToken == null) {
            return false;
        }

        try {
            FeignConfig.setAdminToken(adminToken);
            try {
                KeycloakRole role = adminClient.getRole(realm, roleName);
                return role != null;
            } catch (Exception e) {
                log.error("Error checking if role exists", e);
                return false;
            } finally {
                FeignConfig.clearAdminToken();
            }
        } catch (Exception e) {
            log.error("Error checking if role exists", e);
            return false;
        }
    }

    private boolean verifyRoleAssignment(String userId, String roleName, String adminToken) {
        try {
            FeignConfig.setAdminToken(adminToken);
            try {
                List<KeycloakRole> roles = adminClient.getUserRoles(realm, userId);
                if (roles != null) {
                    log.debug("User roles: {}", roles);
                    return roles.stream()
                            .anyMatch(role -> roleName.equals(role.getName()));
                }
                return false;
            } finally {
                FeignConfig.clearAdminToken();
            }
        } catch (Exception e) {
            log.error("Error verifying role assignment", e);
            return false;
        }
    }

    public void deleteUser(String userId) {
        String adminToken = getAdminToken();
        if (adminToken == null) {
            return;
        }

        try {
            FeignConfig.setAdminToken(adminToken);
            try {
                adminClient.deleteUser(realm, userId);
            } finally {
                FeignConfig.clearAdminToken();
            }
        } catch (Exception e) {
            log.error("Error deleting user", e);
        }
    }

    public Map<String, Object> login(String username, String password) {
        try {
            Map<String, Object> formParams = new HashMap<>();
            formParams.put("grant_type", "password");
            formParams.put("client_id", clientId);
            formParams.put("username", username);
            formParams.put("password", password);
            
            KeycloakTokenResponse response = tokenClient.login(realm, formParams);

            if (response != null) {
                Map<String, Object> result = new HashMap<>();
                result.put("access_token", response.getAccessToken());
                result.put("refresh_token", response.getRefreshToken());
                result.put("id_token", response.getIdToken());
                result.put("token_type", response.getTokenType());
                result.put("expires_in", response.getExpiresIn());
                result.put("refresh_expires_in", response.getRefreshExpiresIn());
                return result;
            } else {
                log.error("Failed to login. Response is null");
                throw new RuntimeException("Invalid username or password");
            }
        } catch (Exception e) {
            log.error("Error during login", e);
            throw new RuntimeException("Login failed: " + e.getMessage(), e);
        }
    }

    public Map<String, Object> refreshToken(String refreshToken) {
        try {
            Map<String, Object> formParams = new HashMap<>();
            formParams.put("grant_type", "refresh_token");
            formParams.put("client_id", clientId);
            formParams.put("refresh_token", refreshToken);
            
            KeycloakTokenResponse response = tokenClient.refreshToken(realm, formParams);

            if (response != null) {
                Map<String, Object> result = new HashMap<>();
                result.put("access_token", response.getAccessToken());
                result.put("refresh_token", response.getRefreshToken());
                result.put("id_token", response.getIdToken());
                result.put("token_type", response.getTokenType());
                result.put("expires_in", response.getExpiresIn());
                result.put("refresh_expires_in", response.getRefreshExpiresIn());
                return result;
            } else {
                log.error("Failed to refresh token. Response is null");
                throw new RuntimeException("Invalid refresh token");
            }
        } catch (Exception e) {
            log.error("Error during token refresh", e);
            throw new RuntimeException("Token refresh failed: " + e.getMessage(), e);
        }
    }

    public UserInfo getUserInfo(String userId) {
        String adminToken = getAdminToken();
        if (adminToken == null) {
            throw new RuntimeException("Failed to authenticate with Keycloak admin");
        }

        try {
            FeignConfig.setAdminToken(adminToken);
            try {
                KeycloakUser keycloakUser = adminClient.getUser(realm, userId);
                if (keycloakUser == null) {
                    throw new RuntimeException("User not found");
                }

                List<String> roles = getUserRoles(userId, adminToken);

                return UserInfo.builder()
                        .id(keycloakUser.getId())
                        .username(keycloakUser.getUsername())
                        .email(keycloakUser.getEmail())
                        .firstName(keycloakUser.getFirstName())
                        .lastName(keycloakUser.getLastName())
                        .enabled(keycloakUser.getEnabled())
                        .emailVerified(keycloakUser.getEmailVerified())
                        .roles(roles)
                        .build();
            } finally {
                FeignConfig.clearAdminToken();
            }
        } catch (Exception e) {
            log.error("Error getting user info", e);
            throw new RuntimeException("Failed to get user info: " + e.getMessage(), e);
        }
    }

    private List<String> getUserRoles(String userId, String adminToken) {
        try {
            FeignConfig.setAdminToken(adminToken);
            try {
                List<KeycloakRole> roles = adminClient.getUserRoles(realm, userId);
                if (roles != null) {
                    return roles.stream()
                            .map(KeycloakRole::getName)
                            .collect(Collectors.toList());
                }
            } finally {
                FeignConfig.clearAdminToken();
            }
        } catch (Exception e) {
            log.error("Error getting user roles", e);
        }
        return Collections.emptyList();
    }

    public void updateUser(String userId, UpdateUserRequest updateRequest) {
        String adminToken = getAdminToken();
        if (adminToken == null) {
            throw new RuntimeException("Failed to authenticate with Keycloak admin");
        }

        try {
            FeignConfig.setAdminToken(adminToken);
            try {
                KeycloakUser keycloakUser = adminClient.getUser(realm, userId);
                if (keycloakUser == null) {
                    throw new RuntimeException("User not found");
                }

                if (updateRequest.getEmail() != null) {
                    keycloakUser.setEmail(updateRequest.getEmail());
                }
                if (updateRequest.getFirstName() != null) {
                    keycloakUser.setFirstName(updateRequest.getFirstName());
                }
                if (updateRequest.getLastName() != null) {
                    keycloakUser.setLastName(updateRequest.getLastName());
                }
                if (updateRequest.getEnabled() != null) {
                    keycloakUser.setEnabled(updateRequest.getEnabled());
                }
                if (updateRequest.getEmailVerified() != null) {
                    keycloakUser.setEmailVerified(updateRequest.getEmailVerified());
                }

                adminClient.updateUser(realm, userId, keycloakUser);
            } catch (Exception e) {
                log.error("Failed to update user", e);
                throw new RuntimeException("Failed to update user", e);
            } finally {
                FeignConfig.clearAdminToken();
            }
        } catch (Exception e) {
            log.error("Error updating user", e);
            throw new RuntimeException("Failed to update user: " + e.getMessage(), e);
        }
    }

    public UserInfo getCurrentUserInfo(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new RuntimeException("Invalid token format");
            }

            String payload = parts[1];
            switch (payload.length() % 4) {
                case 2: payload += "=="; break;
                case 3: payload += "="; break;
            }
            
            String decodedPayload = new String(java.util.Base64.getUrlDecoder().decode(payload));
            Map<String, Object> claims = objectMapper.readValue(decodedPayload, Map.class);

            String userId = (String) claims.get("sub");
            if (userId == null) {
                throw new RuntimeException("User ID not found in token");
            }

            return getUserInfo(userId);
        } catch (Exception e) {
            log.error("Error getting current user info from token", e);
            throw new RuntimeException("Failed to get user info from token: " + e.getMessage(), e);
        }
    }

    public void validateRoleExists(String role) {
        if (!this.roleExists(role)) {
            log.error("Role '{}' does not exist in realm. Please create it in Keycloak first.", role);
            throw new RuntimeException(
                    "Role '" + role + "' does not exist in Keycloak. " +
                            "Please contact administrator or create the role in Keycloak Admin Console.");
        }
    }
}

