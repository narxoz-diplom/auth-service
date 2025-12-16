package com.microservices.authservice.controller;

import com.microservices.authservice.dto.*;
import com.microservices.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegistrationResponse register(@Valid @RequestBody RegistrationRequest request) {
        return authService.register(request);
    }

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request.getUsername(), request.getPassword());
    }

    @PostMapping("/refresh")
    @ResponseStatus(HttpStatus.OK)
    public TokenResponse refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request.getRefreshToken());
    }

    @GetMapping("/user")
    @ResponseStatus(HttpStatus.OK)
    public UserInfo getCurrentUser(Authentication authentication) {
        return authService.getCurrentUser(authentication);
    }

    @GetMapping("/user/{userId}")
    @ResponseStatus(HttpStatus.OK)
    public UserInfo getUser(@PathVariable String userId, Authentication authentication) {
        return authService.getUser(userId, authentication);
    }

    @PutMapping("/user/{userId}")
    @ResponseStatus(HttpStatus.OK)
    public Map<String, String> updateUser(@PathVariable String userId,
                                          @Valid @RequestBody UpdateUserRequest request,
                                          Authentication authentication) {
        authService.updateUser(userId, request, authentication);
        return Map.of("message", "User updated successfully");
    }

    @DeleteMapping("/user/{userId}")
    @ResponseStatus(HttpStatus.OK)
    public Map<String, String> deleteUser(@PathVariable String userId, Authentication authentication) {
        authService.deleteUser(userId, authentication);
        return Map.of("message", "User deleted successfully");
    }
}

