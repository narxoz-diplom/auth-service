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

    private final LocalAuthService localAuthService;

    public RegistrationResponse register(RegistrationRequest request) {
        String role = validateAndNormalizeRole(request.getRole());
        request.setRole(role);

        localAuthService.validateRoleExists(role);
        String userId = localAuthService.createUser(request);
        localAuthService.assignRole(userId, role);

        return RegistrationResponse.builder()
                .message("User registered successfully")
                .username(request.getUsername())
                .roleAssigned(true)
                .build();
    }

    public TokenResponse login(String username, String password) {
        Map<String, Object> tokenData = localAuthService.login(username, password);
        return buildTokenResponse(tokenData);
    }

    public TokenResponse refreshToken(String refreshToken) {
        Map<String, Object> tokenData = localAuthService.refreshToken(refreshToken);
        return buildTokenResponse(tokenData);
    }

    public UserInfo getCurrentUser(Authentication authentication) {
        Jwt jwt = extractJwt(authentication);
        return localAuthService.getCurrentUserInfo(jwt.getTokenValue());
    }

    public UserInfo getUser(String userId, Authentication authentication) {
        Jwt jwt = extractJwt(authentication);
        String currentUserId = jwt.getSubject();

        if (!isAdmin(jwt) && !currentUserId.equals(userId)) {
            throw new ForbiddenException("Access denied");
        }

        return localAuthService.getUserInfo(userId);
    }

    public void updateUser(String userId, UpdateUserRequest request, Authentication authentication) {
        Jwt jwt = extractJwt(authentication);
        String currentUserId = jwt.getSubject();

        if (!isAdmin(jwt) && !currentUserId.equals(userId)) {
            throw new ForbiddenException("Access denied");
        }

        localAuthService.updateUser(userId, request);
    }

    public void deleteUser(String userId, Authentication authentication) {
        Jwt jwt = extractJwt(authentication);

        if (!isAdmin(jwt)) {
            throw new ForbiddenException("Admin access required");
        }

        localAuthService.deleteUser(userId);
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
            Object rolesClaim = jwt.getClaim("roles");
            if (rolesClaim instanceof List && ((List<?>) rolesClaim).contains("admin")) return true;
            Object realmAccess = jwt.getClaim("realm_access");
            if (realmAccess instanceof Map) {
                Object r = ((Map<?, ?>) realmAccess).get("roles");
                if (r instanceof List) return ((List<?>) r).contains("admin");
            }
        } catch (Exception e) {
            log.debug("Could not parse roles claim", e);
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
            throw new DataValidationException("Role must be 'client', 'teacher' or 'admin'");
        }
        String normalizedRole = role.toLowerCase().trim();
        if (!List.of("client", "teacher", "admin").contains(normalizedRole)) {
            throw new DataValidationException("Role must be 'client', 'teacher' or 'admin'");
        }
        return normalizedRole;
    }
}

