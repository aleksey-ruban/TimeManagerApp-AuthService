package com.alekseyruban.timemanagerapp.auth_service.helpers;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private final SecretKey secretKey;

    public JwtService(@Value("${JWT_SECRET}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Long sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .claim("sessionId", sessionId)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(15 * 60)))
                .signWith(secretKey)
                .compact();
    }

    public String generateRefreshToken(Long sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .claim("sessionId", sessionId)
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(30 * 24 * 3600)))
                .signWith(secretKey)
                .compact();
    }
}