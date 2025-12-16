package com.microservices.authservice.service;

import com.microservices.authservice.dto.*;
import com.microservices.authservice.exception.DataValidationException;
import com.microservices.authservice.exception.ForbiddenException;
import com.microservices.authservice.exception.NotFoundException;
import com.microservices.authservice.exception.UnauthorizedException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final KeycloakService keycloakService;

    public RegistrationResponse register(RegistrationRequest request) {
        String role = validateAndNormalizeRole(request.getRole());
        request.setRole(role);

        keycloakService.validateRoleExists(role);

        String userId = keycloakService.createUser(request);

        if (!keycloakService.assignRole(userId, role)) {
            log.warn("Failed to assign role {} to user {}, but user was created.", role, userId);
            throw new RuntimeException("User created but failed to assign role");
        }

        log.info("User registered: {} with role: {}", request.getUsername(), role);
        return RegistrationResponse.builder()
                .message("User registered successfully")
                .username(request.getUsername())
                .roleAssigned(true)
                .build();
    }

    public TokenResponse login(String username, String password) {
        Map<String, Object> tokenData = keycloakService.login(username, password);
        return buildTokenResponse(tokenData);
    }

    public TokenResponse refreshToken(String refreshToken) {
        Map<String, Object> tokenData = keycloakService.refreshToken(refreshToken);
        return buildTokenResponse(tokenData);
    }

    public UserInfo getCurrentUser(Authentication authentication) {
        Jwt jwt = extractJwt(authentication);
        String token = jwt.getTokenValue();
        return keycloakService.getCurrentUserInfo(token);
    }

    public UserInfo getUser(String userId, Authentication authentication) {
        Jwt jwt = extractJwt(authentication);
        String currentUserId = jwt.getSubject();

        if (!isAdmin(jwt) && !currentUserId.equals(userId)) {
            throw new ForbiddenException("Access denied");
        }

        try {
            return keycloakService.getUserInfo(userId);
        } catch (RuntimeException e) {
            throw new NotFoundException(e.getMessage());
        }
    }

    public void updateUser(String userId, UpdateUserRequest request, Authentication authentication) {
        Jwt jwt = extractJwt(authentication);
        String currentUserId = jwt.getSubject();

        if (!isAdmin(jwt) && !currentUserId.equals(userId)) {
            throw new ForbiddenException("Access denied");
        }

        try {
            keycloakService.updateUser(userId, request);
        } catch (RuntimeException e) {
            throw new NotFoundException(e.getMessage());
        }
    }

    public void deleteUser(String userId, Authentication authentication) {
        Jwt jwt = extractJwt(authentication);

        if (!isAdmin(jwt)) {
            throw new ForbiddenException("Admin access required");
        }

        keycloakService.deleteUser(userId);
    }

    private TokenResponse buildTokenResponse(Map<String, Object> tokenData) {
        return TokenResponse.builder()
                .accessToken((String) tokenData.get("access_token"))
                .refreshToken((String) tokenData.get("refresh_token"))
                .idToken((String) tokenData.get("id_token"))
                .tokenType((String) tokenData.get("token_type"))
                .expiresIn(getLongValue(tokenData.get("expires_in")))
                .refreshExpiresIn(getLongValue(tokenData.get("refresh_expires_in")))
                .build();
    }

    private Jwt extractJwt(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt)) {
            throw new UnauthorizedException("Not authenticated");
        }
        return (Jwt) authentication.getPrincipal();
    }

    private boolean isAdmin(Jwt jwt) {
        try {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null) {
                List<String> roles = (List<String>) realmAccess.get("roles");
                return roles != null && roles.contains("admin");
            }
        } catch (Exception e) {
            log.debug("Could not parse realm_access claim", e);
        }
        return false;
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

    private String validateAndNormalizeRole(String role) {
        if (role == null || role.trim().isEmpty()) {
            throw new DataValidationException("Role must be 'client' or 'teacher'");
        }
        
        String normalizedRole = role.toLowerCase().trim();
        
        if (!normalizedRole.equals("client") && !normalizedRole.equals("teacher")) {
            throw new DataValidationException("Role must be 'client' or 'teacher'");
        }
        
        return normalizedRole;
    }
}

