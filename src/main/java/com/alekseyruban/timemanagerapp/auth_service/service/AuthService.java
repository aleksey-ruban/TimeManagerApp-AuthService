package com.alekseyruban.timemanagerapp.auth_service.service;

import com.alekseyruban.timemanagerapp.auth_service.DTO.authSession.*;
import com.alekseyruban.timemanagerapp.auth_service.entity.AuthSession;
import com.alekseyruban.timemanagerapp.auth_service.entity.User;
import com.alekseyruban.timemanagerapp.auth_service.exception.ApiException;
import com.alekseyruban.timemanagerapp.auth_service.exception.ErrorCode;
import com.alekseyruban.timemanagerapp.auth_service.helpers.JwtService;
import com.alekseyruban.timemanagerapp.auth_service.helpers.TokenEncoder;
import com.alekseyruban.timemanagerapp.auth_service.repository.AuthSessionRepository;
import com.alekseyruban.timemanagerapp.auth_service.repository.UserRepository;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final Integer SESSION_EXPIRATION_DAYS = 7;

    private final UserRepository userRepository;
    private final AuthSessionRepository sessionRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenEncoder tokenEncoder;

    private final ApiException invalidAccessToken = new ApiException(
            HttpStatus.UNAUTHORIZED,
            ErrorCode.INVALID_ACCESS_TOKEN,
            "Invalid access token"
    );

    private final ApiException invalidRefreshToken = new ApiException(
            HttpStatus.UNAUTHORIZED,
            ErrorCode.INVALID_REFRESH_TOKEN,
            "Invalid refresh token"
    );

    public AuthResponse login(LoginRequest request) {

        User user = userRepository.findByEmailAndDeletedFalse(request.getEmail())
                .orElseThrow(() -> new ApiException(
                        HttpStatus.UNAUTHORIZED,
                        ErrorCode.USER_NOT_FOUND,
                        "User not found or deleted"
                ));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.INVALID_PASSWORD,
                    "Invalid password"
            );
        }

        if (request.getDeviceModel().isBlank()) {
            throw new ApiException(
                    HttpStatus.BAD_REQUEST,
                    ErrorCode.BAD_PARAMS,
                    "Device model is blank"
            );
        }

        Optional<AuthSession> session = sessionRepository.findByUserIdAndDeviceId(
                user.getId(),
                request.getDeviceId()
        );

        if (session.isEmpty() && request.getIsAutomatic()) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.MANUAL_PASSWORD_REQUIRED,
                    "User must enter password manually"
            );
        }

        AuthSession authSession;
        authSession = session.orElseGet(() -> AuthSession.builder()
                .user(user)
                .deviceId(request.getDeviceId())
                .deviceModel(request.getDeviceModel())
                .createdAt(Instant.now())
                .expiresAt(Instant.now().minus(Duration.ofDays(SESSION_EXPIRATION_DAYS)))
                .lastUsedAt(Instant.now())
                .build());

        if (session.isEmpty()) {
            authSession = sessionRepository.save(authSession);
        }

        String refreshToken = jwtService.generateRefreshToken(authSession.getSessionId());
        String refreshTokenHash = tokenEncoder.hash(refreshToken);

        String accessToken = jwtService.generateAccessToken(user.getId(), authSession.getSessionId());
        String accessTokenHash = tokenEncoder.hash(accessToken);

        authSession.setAccessTokenHash(accessTokenHash);
        authSession.setRefreshTokenHash(refreshTokenHash);
        authSession.setLastUsedAt(Instant.now());

        if (authSession.isExpired()) {
            authSession.setExpiresAt(Instant.now().plus(Duration.ofDays(SESSION_EXPIRATION_DAYS)));
        }

        sessionRepository.save(authSession);

        return new AuthResponse(accessToken, refreshToken);
    }

    public boolean checkAccessTokenValid(TokenValidationRequest request) {
        Optional<AuthSession> sessionOpt = sessionRepository.findBySessionId(request.getSessionId());

        if (sessionOpt.isEmpty()) {
            throw invalidAccessToken;
        }

        AuthSession session = sessionOpt.get();
        if (!tokenEncoder.matches(request.getToken(), session.getAccessTokenHash())) {
            throw invalidAccessToken;
        }

        if (session.isExpired()) {
            throw invalidAccessToken;
        }

        return true;
    }

    private AuthSession checkRefreshTokenValid(RefreshTokensRequest request) {
        Long sessionId;
        try {
            sessionId = jwtService.extractSessionId(request.getRefreshToken());
        } catch (JwtException e) {
            throw invalidRefreshToken;
        }

        Optional<AuthSession> sessionOpt = sessionRepository.findBySessionId(sessionId);
        if (sessionOpt.isEmpty()) {
            throw invalidRefreshToken;
        }

        AuthSession session = sessionOpt.get();
        if (!tokenEncoder.matches(request.getRefreshToken(), session.getRefreshTokenHash())) {
            invalidateSession(session);
            throw invalidRefreshToken;
        }

        if (session.isExpired()) {
            throw invalidRefreshToken;
        }

        return session;
    }

    private void invalidateSession(AuthSession session) {
        session.setExpiresAt(Instant.now());
        session.setAccessTokenHash(null);
        session.setRefreshTokenHash(null);
        sessionRepository.save(session);
    }

    public AuthResponse refreshTokens(RefreshTokensRequest request) {
        AuthSession authSession = checkRefreshTokenValid(request);

        String refreshToken = jwtService.generateRefreshToken(authSession.getSessionId());
        String refreshTokenHash = tokenEncoder.hash(refreshToken);

        String accessToken = jwtService.generateAccessToken(authSession.getUser().getId(), authSession.getSessionId());
        String accessTokenHash = tokenEncoder.hash(accessToken);

        authSession.setAccessTokenHash(accessTokenHash);
        authSession.setRefreshTokenHash(refreshTokenHash);
        authSession.setLastUsedAt(Instant.now());

        sessionRepository.save(authSession);

        return new AuthResponse(accessToken, refreshToken);
    }

    public void logoutSpecificDevice(Long sessionId) {
        AuthSession session = sessionRepository.findBySessionId(sessionId)
                .orElseThrow(() -> new ApiException(
                        HttpStatus.UNAUTHORIZED,
                        ErrorCode.SESSION_NOT_EXISTS,
                        "Session not exists"
                ));
        sessionRepository.delete(session);
    }

    public void logoutAllDevicesExceptCurrent(Long sessionId) {
        AuthSession session = sessionRepository.findBySessionId(sessionId)
                .orElseThrow(() -> invalidAccessToken);

        sessionRepository.deleteAllByUserIdAndSessionIdNot(
                session.getUser().getId(),
                session.getSessionId()
        );
    }

    public UserSessionsResponseDTO getUserSessions(Long currentSessionId) {
        AuthSession currentSession = sessionRepository.findBySessionId(currentSessionId)
                .orElseThrow(() -> new ApiException(
                        HttpStatus.UNAUTHORIZED,
                        ErrorCode.SESSION_NOT_EXISTS,
                        "Session not exists"
                ));

        User user = currentSession.getUser();

        List<AuthSessionResponseDTO> sessions = user.getSessions().stream()
                .sorted((s1, s2) -> s2.getLastUsedAt().compareTo(s1.getLastUsedAt()))
                .map(session -> new AuthSessionResponseDTO(
                        session.getSessionId(),
                        session.getDeviceModel(),
                        session.getCreatedAt(),
                        session.getLastUsedAt()
                ))
                .toList();

        return new UserSessionsResponseDTO(currentSessionId, sessions);
    }
}