package com.alekseyruban.timemanagerapp.auth_service.helpers;

import com.alekseyruban.timemanagerapp.auth_service.exception.ApiException;
import com.alekseyruban.timemanagerapp.auth_service.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private final Integer ACCESS_TOKEN_LIVE = 15 * 60;
    private final Integer REFRESH_TOKEN_LIVE = 7 * 24 * 3600;

    private final SecretKey secretKey;

    public JwtService(@Value("${JWT_SECRET}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Long sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .claim("sessionId", sessionId)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ACCESS_TOKEN_LIVE)))
                .signWith(secretKey)
                .compact();
    }

    public String generateRefreshToken(Long sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .claim("sessionId", sessionId)
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(REFRESH_TOKEN_LIVE)))
                .signWith(secretKey)
                .compact();
    }

    public Long extractSessionId(String token) {
        Claims claims = parseToken(token);
        Date expiration = claims.getExpiration();

        if (expiration != null && expiration.before(new Date())) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.INVALID_REFRESH_TOKEN,
                    "Invalid refresh token"
            );
        }

        return claims.get("sessionId", Long.class);
    }

    private Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}