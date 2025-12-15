package com.microservices.authservice.controller;

import com.microservices.authservice.dto.*;
import com.microservices.authservice.service.KeycloakService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {

    private final KeycloakService keycloakService;

    public AuthController(KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegistrationRequest request) {
        try {
            // Validate role
            String role = request.getRole().toLowerCase().trim();
            if (!role.equals("client") && !role.equals("teacher")) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Role must be 'client' or 'teacher'"));
            }
            request.setRole(role);

            // Check if role exists
            if (!keycloakService.roleExists(role)) {
                log.error("Role '{}' does not exist in realm. Please create it in Keycloak first.", role);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error",
                                "Role '" + role + "' does not exist in Keycloak. " +
                                "Please contact administrator or create the role in Keycloak Admin Console."));
            }

            // Create user
            String userId;
            try {
                userId = keycloakService.createUser(request);
            } catch (IllegalArgumentException e) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(Map.of("error", e.getMessage()));
            } catch (RuntimeException e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("error", "Failed to create user: " + e.getMessage()));
            }

            // Assign role
            boolean roleAssigned = keycloakService.assignRole(userId, role);
            if (!roleAssigned) {
                log.warn("Failed to assign role {} to user {}, but user was created.", role, userId);
                return ResponseEntity.status(HttpStatus.CREATED)
                        .body(Map.of(
                                "message", "User registered successfully, but role assignment failed. " +
                                        "Please contact administrator to assign the role manually.",
                                "username", request.getUsername(),
                                "roleAssigned", false,
                                "warning", "Role '" + role + "' needs to be assigned manually in Keycloak"
                        ));
            }

            log.info("User registered: {} with role: {} (assigned: {})", request.getUsername(), role, roleAssigned);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of(
                            "message", "User registered successfully",
                            "username", request.getUsername(),
                            "roleAssigned", roleAssigned
                    ));

        } catch (Exception e) {
            log.error("Error during registration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Registration failed: " + e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            Map<String, Object> tokenData = keycloakService.login(request.getUsername(), request.getPassword());

            TokenResponse response = TokenResponse.builder()
                    .accessToken((String) tokenData.get("access_token"))
                    .refreshToken((String) tokenData.get("refresh_token"))
                    .idToken((String) tokenData.get("id_token"))
                    .tokenType((String) tokenData.get("token_type"))
                    .expiresIn(getLongValue(tokenData.get("expires_in")))
                    .refreshExpiresIn(getLongValue(tokenData.get("refresh_expires_in")))
                    .build();

            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            log.error("Login failed for user: {}", request.getUsername(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Error during login", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Login failed: " + e.getMessage()));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        try {
            Map<String, Object> tokenData = keycloakService.refreshToken(request.getRefreshToken());

            TokenResponse response = TokenResponse.builder()
                    .accessToken((String) tokenData.get("access_token"))
                    .refreshToken((String) tokenData.get("refresh_token"))
                    .idToken((String) tokenData.get("id_token"))
                    .tokenType((String) tokenData.get("token_type"))
                    .expiresIn(getLongValue(tokenData.get("expires_in")))
                    .refreshExpiresIn(getLongValue(tokenData.get("refresh_expires_in")))
                    .build();

            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            log.error("Token refresh failed", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Error during token refresh", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Token refresh failed: " + e.getMessage()));
        }
    }

    @GetMapping("/user")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        try {
            if (authentication == null || !(authentication.getPrincipal() instanceof Jwt)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Not authenticated"));
            }

            Jwt jwt = (Jwt) authentication.getPrincipal();
            String token = jwt.getTokenValue();
            UserInfo userInfo = keycloakService.getCurrentUserInfo(token);

            return ResponseEntity.ok(userInfo);
        } catch (Exception e) {
            log.error("Error getting current user info", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to get user info: " + e.getMessage()));
        }
    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<?> getUser(@PathVariable String userId, Authentication authentication) {
        try {
            // Check if user is admin or accessing their own info
            if (authentication == null || !(authentication.getPrincipal() instanceof Jwt)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Not authenticated"));
            }

            Jwt jwt = (Jwt) authentication.getPrincipal();
            String currentUserId = jwt.getSubject();
            
            // Check admin role from realm_access.roles
            boolean isAdmin = false;
            try {
                Map<String, Object> realmAccess = jwt.getClaim("realm_access");
                if (realmAccess != null) {
                    @SuppressWarnings("unchecked")
                    List<String> roles = (List<String>) realmAccess.get("roles");
                    if (roles != null && roles.contains("admin")) {
                        isAdmin = true;
                    }
                }
            } catch (Exception e) {
                log.debug("Could not parse realm_access claim", e);
            }

            // Allow if admin or accessing own info
            if (!isAdmin && !currentUserId.equals(userId)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "Access denied"));
            }

            UserInfo userInfo = keycloakService.getUserInfo(userId);
            return ResponseEntity.ok(userInfo);
        } catch (RuntimeException e) {
            log.error("Error getting user info", e);
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Error getting user info", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to get user info: " + e.getMessage()));
        }
    }

    @PutMapping("/user/{userId}")
    public ResponseEntity<?> updateUser(@PathVariable String userId,
                                       @Valid @RequestBody UpdateUserRequest request,
                                       Authentication authentication) {
        try {
            // Check if user is admin or updating their own info
            if (authentication == null || !(authentication.getPrincipal() instanceof Jwt)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Not authenticated"));
            }

            Jwt jwt = (Jwt) authentication.getPrincipal();
            String currentUserId = jwt.getSubject();
            
            // Check admin role from realm_access.roles
            boolean isAdmin = false;
            try {
                Map<String, Object> realmAccess = jwt.getClaim("realm_access");
                if (realmAccess != null) {
                    @SuppressWarnings("unchecked")
                    List<String> roles = (List<String>) realmAccess.get("roles");
                    if (roles != null && roles.contains("admin")) {
                        isAdmin = true;
                    }
                }
            } catch (Exception e) {
                log.debug("Could not parse realm_access claim", e);
            }

            // Allow if admin or updating own info
            if (!isAdmin && !currentUserId.equals(userId)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "Access denied"));
            }

            keycloakService.updateUser(userId, request);
            return ResponseEntity.ok(Map.of("message", "User updated successfully"));
        } catch (RuntimeException e) {
            log.error("Error updating user", e);
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Error updating user", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to update user: " + e.getMessage()));
        }
    }

    @DeleteMapping("/user/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable String userId, Authentication authentication) {
        try {
            // Check if user is admin
            if (authentication == null || !(authentication.getPrincipal() instanceof Jwt)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Not authenticated"));
            }

            Jwt jwt = (Jwt) authentication.getPrincipal();
            
            // Check admin role from realm_access.roles
            boolean isAdmin = false;
            try {
                Map<String, Object> realmAccess = jwt.getClaim("realm_access");
                if (realmAccess != null) {
                    @SuppressWarnings("unchecked")
                    List<String> roles = (List<String>) realmAccess.get("roles");
                    if (roles != null && roles.contains("admin")) {
                        isAdmin = true;
                    }
                }
            } catch (Exception e) {
                log.debug("Could not parse realm_access claim", e);
            }

            if (!isAdmin) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "Admin access required"));
            }

            keycloakService.deleteUser(userId);
            return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
        } catch (Exception e) {
            log.error("Error deleting user", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to delete user: " + e.getMessage()));
        }
    }

    private Long getLongValue(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Long) {
            return (Long) value;
        }
        if (value instanceof Integer) {
            return ((Integer) value).longValue();
        }
        if (value instanceof String) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}

