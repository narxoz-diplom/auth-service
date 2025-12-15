package com.microservices.authservice.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.microservices.authservice.dto.RegistrationRequest;
import com.microservices.authservice.dto.UpdateUserRequest;
import com.microservices.authservice.dto.UserInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;

@Service
@Slf4j
public class KeycloakService {

    @Value("${keycloak.url}")
    private String keycloakUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.admin.username}")
    private String adminUsername;

    @Value("${keycloak.admin.password}")
    private String adminPassword;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public KeycloakService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public String getAdminToken() {
        try {
            String tokenUrl = keycloakUrl + "/realms/master/protocol/openid-connect/token";
            String body = "grant_type=password&client_id=admin-cli&username=" + adminUsername + "&password=" + adminPassword;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                Map<String, Object> tokenData = objectMapper.readValue(response.body(), Map.class);
                return (String) tokenData.get("access_token");
            } else {
                log.error("Failed to get admin token. Status: {}, Body: {}", response.statusCode(), response.body());
            }
        } catch (Exception e) {
            log.error("Error getting admin token", e);
        }
        return null;
    }

    public String createUser(RegistrationRequest registrationRequest) {
        String adminToken = getAdminToken();
        if (adminToken == null) {
            throw new RuntimeException("Failed to authenticate with Keycloak admin");
        }

        try {
            String usersUrl = keycloakUrl + "/admin/realms/" + realm + "/users";

            Map<String, Object> userData = new HashMap<>();
            userData.put("username", registrationRequest.getUsername());
            userData.put("email", registrationRequest.getEmail());
            userData.put("firstName", registrationRequest.getFirstName());
            userData.put("lastName", registrationRequest.getLastName());
            userData.put("enabled", true);
            userData.put("emailVerified", true);

            String jsonBody = objectMapper.writeValueAsString(userData);

            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(usersUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            String userId = null;
            if (response.statusCode() == 201) {
                String location = response.headers().firstValue("Location").orElse(null);
                if (location != null) {
                    userId = location.substring(location.lastIndexOf("/") + 1);
                }
            } else if (response.statusCode() == 409) {
                log.warn("User already exists: {}", registrationRequest.getUsername());
                throw new IllegalArgumentException("User with this username or email already exists");
            } else {
                log.error("Failed to create user. Status: {}, Body: {}", response.statusCode(), response.body());
                throw new RuntimeException("Failed to create user: " + response.body());
            }

            // Set password
            if (userId != null) {
                String passwordUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId + "/reset-password";

                Map<String, Object> passwordData = new HashMap<>();
                passwordData.put("type", "password");
                passwordData.put("value", registrationRequest.getPassword());
                passwordData.put("temporary", false);

                String passwordJson = objectMapper.writeValueAsString(passwordData);

                HttpRequest passwordRequest = HttpRequest.newBuilder()
                        .uri(URI.create(passwordUrl))
                        .header("Authorization", "Bearer " + adminToken)
                        .header("Content-Type", "application/json")
                        .PUT(HttpRequest.BodyPublishers.ofString(passwordJson))
                        .build();

                HttpResponse<String> passwordResponse = httpClient.send(passwordRequest, HttpResponse.BodyHandlers.ofString());

                if (passwordResponse.statusCode() == 204) {
                    log.info("Password set successfully for user: {}", registrationRequest.getUsername());
                    return userId;
                } else {
                    log.error("Failed to set password. Status: {}, Body: {}", passwordResponse.statusCode(), passwordResponse.body());
                    deleteUser(userId);
                    throw new RuntimeException("Failed to set password");
                }
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

            // Get role from realm
            String rolesUrl = keycloakUrl + "/admin/realms/" + realm + "/roles/" + roleName;
            HttpRequest getRoleRequest = HttpRequest.newBuilder()
                    .uri(URI.create(rolesUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .GET()
                    .build();

            HttpResponse<String> roleResponse = httpClient.send(getRoleRequest, HttpResponse.BodyHandlers.ofString());
            if (roleResponse.statusCode() != 200) {
                log.error("Role '{}' not found in realm '{}'. Status: {}, Body: {}",
                        roleName, realm, roleResponse.statusCode(), roleResponse.body());
                return false;
            }

            String roleJson = roleResponse.body();
            log.debug("Retrieved role JSON: {}", roleJson);

            // Assign role to user
            String assignUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm";
            String requestBody = "[" + roleJson + "]";

            HttpRequest assignRequest = HttpRequest.newBuilder()
                    .uri(URI.create(assignUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> assignResponse = httpClient.send(assignRequest, HttpResponse.BodyHandlers.ofString());

            if (assignResponse.statusCode() == 204 || assignResponse.statusCode() == 200) {
                log.info("✅ Role '{}' successfully assigned to user '{}'", roleName, userId);
                return verifyRoleAssignment(userId, roleName, adminToken);
            } else {
                log.error("❌ Failed to assign role '{}' to user '{}'. Status: {}, Body: {}",
                        roleName, userId, assignResponse.statusCode(), assignResponse.body());
                return false;
            }
        } catch (Exception e) {
            log.error("❌ Exception while assigning role '{}' to user '{}': {}", roleName, userId, e.getMessage(), e);
            return false;
        }
    }

    public boolean roleExists(String roleName) {
        String adminToken = getAdminToken();
        if (adminToken == null) {
            return false;
        }

        try {
            String rolesUrl = keycloakUrl + "/admin/realms/" + realm + "/roles/" + roleName;
            HttpRequest getRoleRequest = HttpRequest.newBuilder()
                    .uri(URI.create(rolesUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .GET()
                    .build();

            HttpResponse<String> roleResponse = httpClient.send(getRoleRequest, HttpResponse.BodyHandlers.ofString());
            return roleResponse.statusCode() == 200;
        } catch (Exception e) {
            log.error("Error checking if role exists", e);
            return false;
        }
    }

    private boolean verifyRoleAssignment(String userId, String roleName, String adminToken) {
        try {
            String rolesUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm";
            HttpRequest getRolesRequest = HttpRequest.newBuilder()
                    .uri(URI.create(rolesUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .GET()
                    .build();

            HttpResponse<String> rolesResponse = httpClient.send(getRolesRequest, HttpResponse.BodyHandlers.ofString());
            if (rolesResponse.statusCode() == 200) {
                String rolesJson = rolesResponse.body();
                log.debug("User roles: {}", rolesJson);
                return rolesJson != null && rolesJson.contains("\"name\":\"" + roleName + "\"");
            }
            return false;
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
            String deleteUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId;
            HttpRequest deleteRequest = HttpRequest.newBuilder()
                    .uri(URI.create(deleteUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .DELETE()
                    .build();
            httpClient.send(deleteRequest, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            log.error("Error deleting user", e);
        }
    }

    public Map<String, Object> login(String username, String password) {
        try {
            String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
            String body = "grant_type=password&client_id=" + clientId + "&username=" + username + "&password=" + password;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                return objectMapper.readValue(response.body(), Map.class);
            } else {
                log.error("Failed to login. Status: {}, Body: {}", response.statusCode(), response.body());
                throw new RuntimeException("Invalid username or password");
            }
        } catch (Exception e) {
            log.error("Error during login", e);
            throw new RuntimeException("Login failed: " + e.getMessage(), e);
        }
    }

    public Map<String, Object> refreshToken(String refreshToken) {
        try {
            String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
            String body = "grant_type=refresh_token&client_id=" + clientId + "&refresh_token=" + refreshToken;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                return objectMapper.readValue(response.body(), Map.class);
            } else {
                log.error("Failed to refresh token. Status: {}, Body: {}", response.statusCode(), response.body());
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
            String userUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId;
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(userUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                Map<String, Object> userData = objectMapper.readValue(response.body(), Map.class);

                // Get user roles
                List<String> roles = getUserRoles(userId, adminToken);

                return UserInfo.builder()
                        .id((String) userData.get("id"))
                        .username((String) userData.get("username"))
                        .email((String) userData.get("email"))
                        .firstName((String) userData.get("firstName"))
                        .lastName((String) userData.get("lastName"))
                        .enabled((Boolean) userData.get("enabled"))
                        .emailVerified((Boolean) userData.get("emailVerified"))
                        .roles(roles)
                        .build();
            } else {
                throw new RuntimeException("User not found");
            }
        } catch (Exception e) {
            log.error("Error getting user info", e);
            throw new RuntimeException("Failed to get user info: " + e.getMessage(), e);
        }
    }

    private List<String> getUserRoles(String userId, String adminToken) {
        try {
            String rolesUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm";
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(rolesUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                List<Map<String, Object>> roles = objectMapper.readValue(response.body(), List.class);
                return roles.stream()
                        .map(role -> (String) role.get("name"))
                        .toList();
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
            String userUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId;

            // Get existing user data
            HttpRequest getRequest = HttpRequest.newBuilder()
                    .uri(URI.create(userUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .GET()
                    .build();

            HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
            if (getResponse.statusCode() != 200) {
                throw new RuntimeException("User not found");
            }

            Map<String, Object> userData = objectMapper.readValue(getResponse.body(), Map.class);

            // Update fields
            if (updateRequest.getEmail() != null) {
                userData.put("email", updateRequest.getEmail());
            }
            if (updateRequest.getFirstName() != null) {
                userData.put("firstName", updateRequest.getFirstName());
            }
            if (updateRequest.getLastName() != null) {
                userData.put("lastName", updateRequest.getLastName());
            }
            if (updateRequest.getEnabled() != null) {
                userData.put("enabled", updateRequest.getEnabled());
            }
            if (updateRequest.getEmailVerified() != null) {
                userData.put("emailVerified", updateRequest.getEmailVerified());
            }

            String jsonBody = objectMapper.writeValueAsString(userData);

            HttpRequest putRequest = HttpRequest.newBuilder()
                    .uri(URI.create(userUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .header("Content-Type", "application/json")
                    .PUT(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            HttpResponse<String> putResponse = httpClient.send(putRequest, HttpResponse.BodyHandlers.ofString());
            if (putResponse.statusCode() != 204) {
                log.error("Failed to update user. Status: {}, Body: {}", putResponse.statusCode(), putResponse.body());
                throw new RuntimeException("Failed to update user");
            }
        } catch (Exception e) {
            log.error("Error updating user", e);
            throw new RuntimeException("Failed to update user: " + e.getMessage(), e);
        }
    }

    public UserInfo getCurrentUserInfo(String token) {
        try {
            // Parse JWT token to get user info
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new RuntimeException("Invalid token format");
            }

            // Decode JWT payload (add padding if needed)
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
}

