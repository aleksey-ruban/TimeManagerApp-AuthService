package com.alekseyruban.timemanagerapp.auth_service.service;

import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowCompleteRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowResetPasswordRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowSessionResult;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowStartRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowVerifyRequest;
import com.alekseyruban.timemanagerapp.auth_service.entity.AuthFlowSession;
import com.alekseyruban.timemanagerapp.auth_service.entity.AuthSession;
import com.alekseyruban.timemanagerapp.auth_service.entity.User;
import com.alekseyruban.timemanagerapp.auth_service.exception.ApiException;
import com.alekseyruban.timemanagerapp.auth_service.exception.ErrorCode;
import com.alekseyruban.timemanagerapp.auth_service.helpers.EmailService;
import com.alekseyruban.timemanagerapp.auth_service.repository.AuthFlowSessionRepository;
import com.alekseyruban.timemanagerapp.auth_service.repository.AuthSessionRepository;
import com.alekseyruban.timemanagerapp.auth_service.repository.UserRepository;
import com.alekseyruban.timemanagerapp.auth_service.utils.EmailValidator;
import com.alekseyruban.timemanagerapp.auth_service.utils.PasswordValidator;
import com.alekseyruban.timemanagerapp.auth_service.utils.TextValidator;
import com.alekseyruban.timemanagerapp.auth_service.utils.VerificationGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RegistrationAndResetServiceTest {

    @Mock
    private AuthFlowSessionRepository authFlowSessionRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private BCryptPasswordEncoder passwordEncoder;
    @Mock
    private VerificationGenerator verificationGenerator;
    @Mock
    private EmailValidator emailValidator;
    @Mock
    private EmailService emailService;
    @Mock
    private TextValidator textValidator;
    @Mock
    private PasswordValidator passwordValidator;
    @Mock
    private UserEventPublisher userEventPublisher;
    @Mock
    private AuthSessionRepository authSessionRepository;

    private RegistrationService registrationService;
    private ResetPasswordService resetPasswordService;

    @BeforeEach
    void setUp() {
        registrationService = new RegistrationService(
                authFlowSessionRepository,
                userRepository,
                passwordEncoder,
                verificationGenerator,
                emailValidator,
                emailService,
                textValidator,
                passwordValidator,
                userEventPublisher
        );
        resetPasswordService = new ResetPasswordService(
                authFlowSessionRepository,
                userRepository,
                passwordEncoder,
                verificationGenerator,
                emailValidator,
                emailService,
                passwordValidator,
                authSessionRepository
        );
    }

    @Test
    void startRegistrationRejectsExistingUser() {
        AuthFlowStartRequest request = startRequest("user@example.com");
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.of(user("user@example.com")));

        assertThatThrownBy(() -> registrationService.startRegistration(request))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.EMAIL_ALREADY_REGISTERED);
    }

    @Test
    void startRegistrationRejectsInvalidEmailDomain() {
        AuthFlowStartRequest request = startRequest("user@example.com");
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.empty());
        when(authFlowSessionRepository.findByEmail("user@example.com")).thenReturn(Optional.empty());
        when(emailValidator.isEmailPotentiallyValid("user@example.com")).thenReturn(false);

        assertThatThrownBy(() -> registrationService.startRegistration(request))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.INVALID_EMAIL_DOMAIN);
    }

    @Test
    void startRegistrationCreatesSessionAndSendsMail() {
        AuthFlowStartRequest request = startRequest("user@example.com");
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.empty());
        when(authFlowSessionRepository.findByEmail("user@example.com")).thenReturn(Optional.empty());
        when(emailValidator.isEmailPotentiallyValid("user@example.com")).thenReturn(true);
        when(verificationGenerator.generateEmailCode()).thenReturn("123456");
        when(verificationGenerator.generateSessionToken()).thenReturn("session-token");
        when(passwordEncoder.encode("123456")).thenReturn("code-hash");
        when(passwordEncoder.encode("session-token")).thenReturn("session-hash");
        when(authFlowSessionRepository.save(any(AuthFlowSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AuthFlowSessionResult result = registrationService.startRegistration(request);

        assertThat(result.getSessionToken()).isEqualTo("session-token");
        verify(emailService).sendVerificationCode("user@example.com", "123456", "ru");
    }

    @Test
    void verifyCodeMarksSessionVerified() {
        AuthFlowSession session = validFlowSession("user@example.com");
        when(authFlowSessionRepository.findByEmail("user@example.com")).thenReturn(Optional.of(session));
        when(passwordEncoder.matches("session-token", "session-hash")).thenReturn(true);
        when(passwordEncoder.matches("123456", "code-hash")).thenReturn(true);
        AuthFlowVerifyRequest request = new AuthFlowVerifyRequest();
        request.setEmail("user@example.com");
        request.setCode("123456");

        registrationService.verifyCode(request, "session-token");

        assertThat(session.isVerified()).isTrue();
        verify(authFlowSessionRepository).save(session);
    }

    @Test
    void completeRegistrationRejectsUnverifiedEmail() {
        AuthFlowSession session = validFlowSession("user@example.com");
        session.setVerified(false);
        when(authFlowSessionRepository.findByEmail("user@example.com")).thenReturn(Optional.of(session));
        when(passwordEncoder.matches("session-token", "session-hash")).thenReturn(true);
        AuthFlowCompleteRequest request = completeRequest("user@example.com");

        assertThatThrownBy(() -> registrationService.completeRegistration(request, "session-token"))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.EMAIL_NOT_VERIFIED);
    }

    @Test
    void completeRegistrationCreatesUserAndPublishesEvent() {
        AuthFlowSession session = validFlowSession("user@example.com");
        when(authFlowSessionRepository.findByEmail("user@example.com")).thenReturn(Optional.of(session));
        when(passwordEncoder.matches("session-token", "session-hash")).thenReturn(true);
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.empty());
        when(textValidator.isValidName("Alice")).thenReturn(true);
        when(passwordValidator.isValid("Password1!")).thenReturn(true);
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Password1!")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User saved = invocation.getArgument(0);
            saved.setId(9L);
            return saved;
        });
        AuthFlowCompleteRequest request = completeRequest("user@example.com");

        registrationService.completeRegistration(request, "session-token");

        verify(userEventPublisher).publishUserCreated(any());
        verify(authFlowSessionRepository).delete(session);
    }

    @Test
    void startResetPasswordRejectsUnknownUser() {
        AuthFlowStartRequest request = startRequest("user@example.com");
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> resetPasswordService.startResettingPassword(request))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.USER_NOT_FOUND);
    }

    @Test
    void startResetPasswordCreatesSessionAndSendsResetCode() {
        AuthFlowStartRequest request = startRequest("user@example.com");
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.of(user("user@example.com")));
        when(authFlowSessionRepository.findByEmail("user@example.com")).thenReturn(Optional.empty());
        when(emailValidator.isEmailPotentiallyValid("user@example.com")).thenReturn(true);
        when(verificationGenerator.generateEmailCode()).thenReturn("123456");
        when(verificationGenerator.generateSessionToken()).thenReturn("session-token");
        when(passwordEncoder.encode("123456")).thenReturn("code-hash");
        when(passwordEncoder.encode("session-token")).thenReturn("session-hash");
        when(authFlowSessionRepository.save(any(AuthFlowSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AuthFlowSessionResult result = resetPasswordService.startResettingPassword(request);

        assertThat(result.getSessionToken()).isEqualTo("session-token");
        verify(emailService).sendResetCode("user@example.com", "123456", "ru");
    }

    @Test
    void resendResetCodeRejectsVerifiedSession() {
        AuthFlowSession session = validFlowSession("user@example.com");
        session.setVerified(true);
        when(authFlowSessionRepository.findByEmail("user@example.com")).thenReturn(Optional.of(session));
        when(passwordEncoder.matches("session-token", "session-hash")).thenReturn(true);

        assertThatThrownBy(() -> resetPasswordService.resendCode(startRequest("user@example.com"), "session-token"))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.EMAIL_ALREADY_VERIFIED);
    }

    @Test
    void completeResetPasswordRejectsWeakPassword() {
        User user = user("user@example.com");
        AuthFlowSession session = validFlowSession("user@example.com");
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.of(user));
        when(authFlowSessionRepository.findByEmail("user@example.com")).thenReturn(Optional.of(session));
        when(passwordEncoder.matches("session-token", "session-hash")).thenReturn(true);
        when(passwordValidator.isValid("weak")).thenReturn(false);
        AuthFlowResetPasswordRequest request = resetRequest("user@example.com");
        request.setNewPassword("weak");

        assertThatThrownBy(() -> resetPasswordService.completeResettingPassword(request, "session-token"))
                .isInstanceOf(ApiException.class)
                .extracting("code")
                .isEqualTo(ErrorCode.BAD_PASSWORD);
    }

    @Test
    void completeResetPasswordUpdatesPasswordDeletesFlowAndKeepsCurrentDevice() {
        User user = user("user@example.com");
        user.setId(5L);
        AuthFlowSession flowSession = validFlowSession("user@example.com");
        UUID currentDevice = UUID.randomUUID();
        AuthSession current = AuthSession.builder().sessionId(1L).deviceId(currentDevice).build();
        AuthSession other = AuthSession.builder().sessionId(2L).deviceId(UUID.randomUUID()).build();
        when(userRepository.findByEmailAndDeletedFalse("user@example.com")).thenReturn(Optional.of(user));
        when(authFlowSessionRepository.findByEmail("user@example.com")).thenReturn(Optional.of(flowSession));
        when(passwordEncoder.matches("session-token", "session-hash")).thenReturn(true);
        when(passwordValidator.isValid("Password1!")).thenReturn(true);
        when(passwordEncoder.encode("Password1!")).thenReturn("encoded-password");
        when(authSessionRepository.findAllByUserId(5L)).thenReturn(List.of(current, other));
        AuthFlowResetPasswordRequest request = resetRequest("user@example.com");
        request.setDeviceId(currentDevice);

        resetPasswordService.completeResettingPassword(request, "session-token");

        assertThat(user.getPassword()).isEqualTo("encoded-password");
        verify(userRepository).save(user);
        verify(authFlowSessionRepository).delete(flowSession);
        verify(authSessionRepository).delete(other);
    }

    private AuthFlowStartRequest startRequest(String email) {
        AuthFlowStartRequest request = new AuthFlowStartRequest();
        request.setEmail(email);
        request.setLocal("ru");
        return request;
    }

    private AuthFlowCompleteRequest completeRequest(String email) {
        AuthFlowCompleteRequest request = new AuthFlowCompleteRequest();
        request.setEmail(email);
        request.setFirstName("Alice");
        request.setPassword("Password1!");
        return request;
    }

    private AuthFlowResetPasswordRequest resetRequest(String email) {
        AuthFlowResetPasswordRequest request = new AuthFlowResetPasswordRequest();
        request.setEmail(email);
        request.setNewPassword("Password1!");
        request.setDeviceId(UUID.randomUUID());
        return request;
    }

    private AuthFlowSession validFlowSession(String email) {
        return AuthFlowSession.builder()
                .email(email)
                .sessionTokenHash("session-hash")
                .verificationCodeHash("code-hash")
                .verified(true)
                .createdAt(Instant.now().minusSeconds(120))
                .lastCodeSentAt(Instant.now().minusSeconds(120))
                .expiresAt(Instant.now().plusSeconds(600))
                .build();
    }

    private User user(String email) {
        return User.builder()
                .email(email)
                .firstName("John")
                .password("old-password")
                .build();
    }
}
