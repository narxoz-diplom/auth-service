package com.microservices.authservice.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@Slf4j
public class JwtService {

    private final SecretKey key;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-ttl-seconds:3600}") long accessTtlSeconds,
            @Value("${jwt.refresh-ttl-seconds:604800}") long refreshTtlSeconds) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
    }

    public String createAccessToken(String userId, String username, List<String> roles) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + accessTtlSeconds * 1000L);
        return Jwts.builder()
                .subject(userId)
                .claim("preferred_username", username)
                .claim("realm_access", Map.of("roles", roles))
                .claim("resource_access", Map.of("microservices-client", Map.of("roles", roles)))
                .claim("roles", roles)
                .issuedAt(now)
                .expiration(exp)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public String createRefreshToken(String userId) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + refreshTtlSeconds * 1000L);
        return Jwts.builder()
                .subject(userId)
                .claim("type", "refresh")
                .issuedAt(now)
                .expiration(exp)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public Jws<Claims> parseToken(String token) {
        try {
            return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
        } catch (JwtException e) {
            log.debug("Invalid token: {}", e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> getRoles(Claims claims) {
        Object realmAccess = claims.get("realm_access");
        if (realmAccess instanceof Map) {
            Object roles = ((Map<?, ?>) realmAccess).get("roles");
            if (roles instanceof List) {
                return ((List<?>) roles).stream().map(String::valueOf).collect(Collectors.toList());
            }
        }
        Object rolesClaim = claims.get("roles");
        if (rolesClaim instanceof List) {
            return ((List<?>) rolesClaim).stream().map(String::valueOf).collect(Collectors.toList());
        }
        return List.of();
    }
}
