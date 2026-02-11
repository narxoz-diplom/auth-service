package com.microservices.authservice.service;

import com.microservices.authservice.dto.RegistrationRequest;
import com.microservices.authservice.dto.UpdateUserRequest;
import com.microservices.authservice.dto.UserInfo;
import com.microservices.authservice.exception.NotFoundException;
import com.microservices.authservice.model.User;
import com.microservices.authservice.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class LocalAuthService {

    private static final List<String> VALID_ROLES = List.of("admin", "teacher", "client");

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public void validateRoleExists(String role) {
        if (role == null || !VALID_ROLES.contains(role.toLowerCase())) {
            throw new IllegalArgumentException("Role must be one of: admin, teacher, client");
        }
    }

    @Transactional
    public String createUser(RegistrationRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("User with this username already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("User with this email already exists");
        }
        String role = request.getRole().toLowerCase().trim();
        validateRoleExists(role);

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .role(role)
                .enabled(true)
                .build();
        user = userRepository.save(user);
        log.info("User registered: {} with role: {}", request.getUsername(), role);
        return user.getId();
    }

    public boolean assignRole(String userId, String roleName) {
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) return false;
        user.setRole(roleName.toLowerCase().trim());
        userRepository.save(user);
        return true;
    }

    public Map<String, Object> login(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Invalid username or password"));
        if (!user.getEnabled()) {
            throw new IllegalArgumentException("User is disabled");
        }
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid username or password");
        }
        return buildTokenMap(user);
    }

    public Map<String, Object> refreshToken(String refreshToken) {
        Jws<Claims> jws = jwtService.parseToken(refreshToken);
        if (jws == null || !"refresh".equals(jws.getPayload().get("type"))) {
            throw new IllegalArgumentException("Invalid refresh token");
        }
        String userId = jws.getPayload().getSubject();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        if (!user.getEnabled()) {
            throw new IllegalArgumentException("User is disabled");
        }
        return buildTokenMap(user);
    }

    public UserInfo getCurrentUserInfo(String accessToken) {
        Jws<Claims> jws = jwtService.parseToken(accessToken);
        if (jws == null) throw new IllegalArgumentException("Invalid token");
        String userId = jws.getPayload().getSubject();
        return getUserInfo(userId);
    }

    public UserInfo getUserInfo(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found"));
        return toUserInfo(user);
    }

    @Transactional
    public void updateUser(String userId, UpdateUserRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found"));
        if (request.getFirstName() != null) user.setFirstName(request.getFirstName());
        if (request.getLastName() != null) user.setLastName(request.getLastName());
        if (request.getEmail() != null) user.setEmail(request.getEmail());
        userRepository.save(user);
    }

    @Transactional
    public void deleteUser(String userId) {
        if (!userRepository.existsById(userId)) {
            throw new NotFoundException("User not found");
        }
        userRepository.deleteById(userId);
    }

    private Map<String, Object> buildTokenMap(User user) {
        List<String> roles = List.of(user.getRole());
        String accessToken = jwtService.createAccessToken(user.getId(), user.getUsername(), roles);
        String refreshToken = jwtService.createRefreshToken(user.getId());
        Map<String, Object> map = new HashMap<>();
        map.put("access_token", accessToken);
        map.put("refresh_token", refreshToken);
        map.put("token_type", "Bearer");
        map.put("expires_in", 3600L);
        map.put("refresh_expires_in", 604800L);
        return map;
    }

    private UserInfo toUserInfo(User user) {
        return UserInfo.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .enabled(user.getEnabled())
                .emailVerified(true)
                .roles(List.of(user.getRole()))
                .build();
    }
}
