package com.alekseyruban.timemanagerapp.auth_service.service;

import com.alekseyruban.timemanagerapp.auth_service.DTO.authSession.AuthResponse;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authSession.LoginRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authSession.TokenValidationRequest;
import com.alekseyruban.timemanagerapp.auth_service.entity.AuthSession;
import com.alekseyruban.timemanagerapp.auth_service.entity.User;
import com.alekseyruban.timemanagerapp.auth_service.exception.ApiException;
import com.alekseyruban.timemanagerapp.auth_service.exception.ErrorCode;
import com.alekseyruban.timemanagerapp.auth_service.helpers.JwtService;
import com.alekseyruban.timemanagerapp.auth_service.helpers.TokenEncoder;
import com.alekseyruban.timemanagerapp.auth_service.repository.AuthSessionRepository;
import com.alekseyruban.timemanagerapp.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
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

        String accessToken = jwtService.generateAccessToken(authSession.getSessionId());
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
            return false;
        }

        AuthSession session = sessionOpt.get();
        if (!tokenEncoder.matches(request.getToken(), session.getAccessTokenHash())) {
            return false;
        }

        return !session.isExpired();
    }

    public boolean checkRefreshTokenValid(TokenValidationRequest request) {
        Optional<AuthSession> sessionOpt = sessionRepository.findBySessionId(request.getSessionId());

        if (sessionOpt.isEmpty()) {
            return false;
        }

        AuthSession session = sessionOpt.get();
        if (!tokenEncoder.matches(request.getToken(), session.getRefreshTokenHash())) {
            return false;
        }

        return !session.isExpired();
    }
}