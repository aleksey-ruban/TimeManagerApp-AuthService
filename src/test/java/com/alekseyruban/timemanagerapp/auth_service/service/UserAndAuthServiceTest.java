package com.alekseyruban.timemanagerapp.auth_service.service;

import com.alekseyruban.timemanagerapp.auth_service.DTO.authSession.LoginRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authSession.RefreshTokensRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authSession.TokenValidationRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authSession.UserSessionsResponseDTO;
import com.alekseyruban.timemanagerapp.auth_service.DTO.userOperations.UserResponseDTO;
import com.alekseyruban.timemanagerapp.auth_service.entity.AuthSession;
import com.alekseyruban.timemanagerapp.auth_service.entity.User;
import com.alekseyruban.timemanagerapp.auth_service.exception.ApiException;
import com.alekseyruban.timemanagerapp.auth_service.exception.ErrorCode;
import com.alekseyruban.timemanagerapp.auth_service.helpers.JwtService;
import com.alekseyruban.timemanagerapp.auth_service.repository.AuthSessionRepository;
import com.alekseyruban.timemanagerapp.auth_service.repository.UserRepository;
import com.alekseyruban.timemanagerapp.auth_service.utils.TextValidator;
import com.alekseyruban.timemanagerapp.auth_service.utils.TokenEncoder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserAndAuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private AuthSessionRepository authSessionRepository;
    @Mock
    private TextValidator textValidator;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @Mock
    private TokenEncoder tokenEncoder;

    private UserService userService;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userService = new UserService(userRepository, authSessionRepository, textValidator);
        authService = new AuthService(userRepository, authSessionRepository, passwordEncoder, jwtService, tokenEncoder);
    }

    @Test
    void getUserReturnsUserInfoFromSession() {
        User user = user(1L, "user@example.com");
        AuthSession session = session(10L, user);
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.of(session));
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.of(user));

        UserResponseDTO response = userService.getUser(10L);

        assertThat(response.getEmail()).isEqualTo("user@example.com");
        assertThat(response.getFirstName()).isEqualTo("John");
    }

    @Test
    void updateFirstNameRejectsInvalidName() {
        User user = user(1L, "user@example.com");
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.of(session(10L, user)));
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.of(user));
        when(textValidator.isValidName("!")).thenReturn(false);

        assertThatThrownBy(() -> userService.updateFirstName(10L, "!"))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.BAD_NAME);
    }

    @Test
    void updateFirstNamePersistsNewName() {
        User user = user(1L, "user@example.com");
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.of(session(10L, user)));
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.of(user));
        when(textValidator.isValidName("Alice")).thenReturn(true);

        userService.updateFirstName(10L, "Alice");

        assertThat(user.getFirstName()).isEqualTo("Alice");
        verify(userRepository).save(user);
    }

    @Test
    void softDeleteUserMarksUserDeletedAndRemovesSessions() {
        User user = user(1L, "user@example.com");
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.of(session(10L, user)));
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.of(user));

        userService.softDeleteUser(10L);

        assertThat(user.isDeleted()).isTrue();
        assertThat(user.getDeletedAt()).isNotNull();
        verify(authSessionRepository).deleteAllByUserId(1L);
        verify(userRepository).save(user);
    }

    @Test
    void loginRejectsUnknownUser() {
        LoginRequest request = loginRequest(false);
        when(userRepository.findByEmailAndDeletedFalse(request.getEmail())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.USER_NOT_FOUND);
    }

    @Test
    void loginRejectsWrongPassword() {
        LoginRequest request = loginRequest(false);
        User user = user(1L, request.getEmail());
        when(userRepository.findByEmailAndDeletedFalse(request.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(request.getPassword(), user.getPassword())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.INVALID_PASSWORD);
    }

    @Test
    void loginRejectsBlankDeviceModel() {
        LoginRequest request = loginRequest(false);
        request.setDeviceModel(" ");
        User user = user(1L, request.getEmail());
        when(userRepository.findByEmailAndDeletedFalse(request.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(request.getPassword(), user.getPassword())).thenReturn(true);

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.BAD_PARAMS);
    }

    @Test
    void loginRejectsAutomaticLoginWithoutExistingSession() {
        LoginRequest request = loginRequest(true);
        User user = user(1L, request.getEmail());
        when(userRepository.findByEmailAndDeletedFalse(request.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(request.getPassword(), user.getPassword())).thenReturn(true);
        when(authSessionRepository.findByUserIdAndDeviceId(1L, request.getDeviceId())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.MANUAL_PASSWORD_REQUIRED);
    }

    @Test
    void loginCreatesOrUpdatesSessionAndReturnsTokens() {
        LoginRequest request = loginRequest(false);
        User user = user(1L, request.getEmail());
        when(userRepository.findByEmailAndDeletedFalse(request.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(request.getPassword(), user.getPassword())).thenReturn(true);
        when(authSessionRepository.findByUserIdAndDeviceId(1L, request.getDeviceId())).thenReturn(Optional.empty());
        when(authSessionRepository.save(any(AuthSession.class))).thenAnswer(invocation -> {
            AuthSession session = invocation.getArgument(0);
            if (session.getSessionId() == null) {
                session.setSessionId(15L);
            }
            return session;
        });
        when(jwtService.generateRefreshToken(15L)).thenReturn("refresh");
        when(jwtService.generateAccessToken(1L, 15L)).thenReturn("access");
        when(tokenEncoder.hash("refresh")).thenReturn("refresh-hash");
        when(tokenEncoder.hash("access")).thenReturn("access-hash");

        var response = authService.login(request);

        assertThat(response.getAccessToken()).isEqualTo("access");
        assertThat(response.getRefreshToken()).isEqualTo("refresh");
        verify(authSessionRepository, times(2)).save(any(AuthSession.class));
    }

    @Test
    void checkAccessTokenValidRejectsUnknownSession() {
        TokenValidationRequest request = new TokenValidationRequest();
        request.setSessionId(10L);
        request.setToken("access");
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.checkAccessTokenValid(request))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.INVALID_ACCESS_TOKEN);
    }

    @Test
    void checkAccessTokenValidRejectsMismatchedHash() {
        User user = user(1L, "user@example.com");
        AuthSession session = session(10L, user);
        session.setAccessTokenHash("stored");
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.of(session));
        when(tokenEncoder.matches("access", "stored")).thenReturn(false);
        TokenValidationRequest request = new TokenValidationRequest();
        request.setSessionId(10L);
        request.setToken("access");

        assertThatThrownBy(() -> authService.checkAccessTokenValid(request))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void checkAccessTokenValidReturnsTrueForValidSession() {
        User user = user(1L, "user@example.com");
        AuthSession session = session(10L, user);
        session.setAccessTokenHash("stored");
        session.setExpiresAt(Instant.now().plusSeconds(60));
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.of(session));
        when(tokenEncoder.matches("access", "stored")).thenReturn(true);
        TokenValidationRequest request = new TokenValidationRequest();
        request.setSessionId(10L);
        request.setToken("access");

        assertThat(authService.checkAccessTokenValid(request)).isTrue();
    }

    @Test
    void refreshTokensInvalidatesSessionWhenStoredHashDoesNotMatch() {
        User user = user(1L, "user@example.com");
        AuthSession session = session(10L, user);
        session.setRefreshTokenHash("stored");
        session.setExpiresAt(Instant.now().plusSeconds(60));
        RefreshTokensRequest request = new RefreshTokensRequest();
        request.setRefreshToken("refresh");
        when(jwtService.extractSessionId("refresh")).thenReturn(10L);
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.of(session));
        when(tokenEncoder.matches("refresh", "stored")).thenReturn(false);

        assertThatThrownBy(() -> authService.refreshTokens(request))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
        assertThat(session.getAccessTokenHash()).isNull();
        assertThat(session.getRefreshTokenHash()).isNull();
        verify(authSessionRepository).save(session);
    }

    @Test
    void refreshTokensReturnsNewTokensForValidSession() {
        User user = user(1L, "user@example.com");
        AuthSession session = session(10L, user);
        session.setRefreshTokenHash("stored");
        session.setExpiresAt(Instant.now().plusSeconds(60));
        RefreshTokensRequest request = new RefreshTokensRequest();
        request.setRefreshToken("refresh");
        when(jwtService.extractSessionId("refresh")).thenReturn(10L);
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.of(session));
        when(tokenEncoder.matches("refresh", "stored")).thenReturn(true);
        when(jwtService.generateRefreshToken(10L)).thenReturn("new-refresh");
        when(jwtService.generateAccessToken(1L, 10L)).thenReturn("new-access");
        when(tokenEncoder.hash("new-refresh")).thenReturn("new-refresh-hash");
        when(tokenEncoder.hash("new-access")).thenReturn("new-access-hash");

        var response = authService.refreshTokens(request);

        assertThat(response.getAccessToken()).isEqualTo("new-access");
        assertThat(response.getRefreshToken()).isEqualTo("new-refresh");
    }

    @Test
    void logoutSpecificDeviceDeletesSession() {
        User user = user(1L, "user@example.com");
        AuthSession session = session(10L, user);
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.of(session));

        authService.logoutSpecificDevice(10L);

        verify(authSessionRepository).delete(session);
    }

    @Test
    void logoutAllDevicesExceptCurrentDeletesOtherSessions() {
        User user = user(1L, "user@example.com");
        AuthSession session = session(10L, user);
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.of(session));

        authService.logoutAllDevicesExceptCurrent(10L);

        verify(authSessionRepository).deleteAllByUserIdAndSessionIdNot(1L, 10L);
    }

    @Test
    void getUserSessionsSortsSessionsByLastUsedAtDescending() {
        User user = user(1L, "user@example.com");
        AuthSession older = session(10L, user);
        older.setDeviceModel("old");
        older.setCreatedAt(Instant.now().minusSeconds(200));
        older.setLastUsedAt(Instant.now().minusSeconds(100));
        AuthSession newer = session(11L, user);
        newer.setDeviceModel("new");
        newer.setCreatedAt(Instant.now().minusSeconds(50));
        newer.setLastUsedAt(Instant.now().minusSeconds(10));
        user.setSessions(List.of(older, newer));
        when(authSessionRepository.findBySessionId(10L)).thenReturn(Optional.of(older));

        UserSessionsResponseDTO response = authService.getUserSessions(10L);

        assertThat(response.getSessions()).extracting("sessionId").containsExactly(11L, 10L);
    }

    private LoginRequest loginRequest(boolean automatic) {
        LoginRequest request = new LoginRequest();
        request.setEmail("user@example.com");
        request.setPassword("Password1!");
        request.setDeviceId(UUID.randomUUID());
        request.setDeviceModel("iPhone");
        request.setIsAutomatic(automatic);
        return request;
    }

    private User user(Long id, String email) {
        return User.builder()
                .id(id)
                .email(email)
                .password("encoded")
                .firstName("John")
                .build();
    }

    private AuthSession session(Long sessionId, User user) {
        return AuthSession.builder()
                .sessionId(sessionId)
                .user(user)
                .deviceId(UUID.randomUUID())
                .deviceModel("iPhone")
                .createdAt(Instant.now().minusSeconds(100))
                .lastUsedAt(Instant.now().minusSeconds(50))
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }
}
