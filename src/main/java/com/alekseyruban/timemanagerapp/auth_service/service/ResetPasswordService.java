package com.alekseyruban.timemanagerapp.auth_service.service;

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
import com.alekseyruban.timemanagerapp.auth_service.helpers.EmailValidator;
import com.alekseyruban.timemanagerapp.auth_service.helpers.PasswordValidator;
import com.alekseyruban.timemanagerapp.auth_service.helpers.VerificationGenerator;
import com.alekseyruban.timemanagerapp.auth_service.repository.AuthFlowSessionRepository;
import com.alekseyruban.timemanagerapp.auth_service.repository.AuthSessionRepository;
import com.alekseyruban.timemanagerapp.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ResetPasswordService {

    private final AuthFlowSessionRepository sessionRepository;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final VerificationGenerator generator;
    private final EmailValidator emailValidator;
    private final EmailService emailService;
    private final PasswordValidator passwordValidator;
    private final AuthSessionRepository authSessionRepository;

    public AuthFlowSessionResult startResettingPassword(AuthFlowStartRequest request) {
        if (userRepository.findByEmailAndDeletedFalse(request.getEmail()).isEmpty()) {
            throw new ApiException(
                    HttpStatus.NOT_FOUND,
                    ErrorCode.USER_NOT_FOUND,
                    "User with given email not found"
            );
        }

        if (sessionRepository.findByEmail(request.getEmail()).isPresent()) {
            AuthFlowSession session = sessionRepository.findByEmail(request.getEmail()).get();
            if (session.isCreatedWithinOneMinute()) {
                throw new ApiException(
                        HttpStatus.TOO_MANY_REQUESTS,
                        ErrorCode.EMAIL_COOL_DOWN,
                        "Wait 1 minute and try again"
                );
            } else {
                sessionRepository.delete(session);
            }
        }

        if (!emailValidator.isEmailPotentiallyValid(request.getEmail())) {
            throw new ApiException(
                    HttpStatus.BAD_REQUEST,
                    ErrorCode.INVALID_EMAIL_DOMAIN,
                    "Email is not valid"
            );
        }

        String code = generator.generateEmailCode();
        String codeHash = passwordEncoder.encode(code);

        String sessionToken = generator.generateSessionToken();
        String sessionTokenHash = passwordEncoder.encode(sessionToken);

        AuthFlowSession session = AuthFlowSession.builder()
                .email(request.getEmail())
                .verificationCodeHash(codeHash)
                .sessionTokenHash(sessionTokenHash)
                .verified(false)
                .createdAt(Instant.now())
                .lastCodeSentAt(Instant.now())
                .expiresAt(Instant.now().plus(Duration.ofMinutes(15)))
                .build();

        sessionRepository.save(session);

        emailService.sendResetCode(request.getEmail(), code, request.getLocal());

        return AuthFlowSessionResult.builder()
                .sessionToken(sessionToken)
                .expiresAt(session.getExpiresAt())
                .build();
    }

    public void resendCode(AuthFlowStartRequest request, String sessionToken) {
        AuthFlowSession session = sessionRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ApiException(
                                HttpStatus.UNAUTHORIZED,
                                ErrorCode.SESSION_NOT_EXISTS,
                                "Session does not exists"
                        )
                );

        if (!passwordEncoder.matches(sessionToken, session.getSessionTokenHash())) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.SESSION_NOT_EXISTS,
                    "Invalid session (token)"
            );
        }

        if (session.isExpired()) {
            sessionRepository.delete(session);
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.SESSION_EXPIRED,
                    "Session expired"
            );
        }

        if (session.isCodeSentWithinOneMinute()) {
            throw new ApiException(
                    HttpStatus.TOO_MANY_REQUESTS,
                    ErrorCode.EMAIL_COOL_DOWN,
                    "Wait 1 minute to resend code"
            );
        }

        if (session.isVerified()) {
            throw new ApiException(
                    HttpStatus.CONFLICT,
                    ErrorCode.EMAIL_ALREADY_VERIFIED,
                    "Email already verified"
            );
        }

        String newCode = generator.generateEmailCode();
        session.setVerificationCodeHash(passwordEncoder.encode(newCode));
        session.setLastCodeSentAt(Instant.now());
        sessionRepository.save(session);

        emailService.resendResetCode(request.getEmail(), newCode, request.getLocal());
    }

    public void verifyCode(AuthFlowVerifyRequest request, String sessionToken) {
        AuthFlowSession session = sessionRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ApiException(
                                HttpStatus.UNAUTHORIZED,
                                ErrorCode.SESSION_NOT_EXISTS,
                                "Session does not exists"
                        )
                );

        if (!passwordEncoder.matches(sessionToken, session.getSessionTokenHash())) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.SESSION_NOT_EXISTS,
                    "Invalid session (token)"
            );
        }

        if (session.isExpired()) {
            sessionRepository.delete(session);
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.SESSION_EXPIRED,
                    "Session expired"
            );
        }

        if (!passwordEncoder.matches(request.getCode(), session.getVerificationCodeHash())) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.INVALID_CODE,
                    "Invalid verification code"
            );
        }

        session.setVerified(true);
        sessionRepository.save(session);
    }

    public void completeResettingPassword(AuthFlowResetPasswordRequest request, String sessionToken) {
        User user = userRepository.findByEmailAndDeletedFalse(request.getEmail())
                .orElseThrow(() -> new ApiException(
                                HttpStatus.NOT_FOUND,
                                ErrorCode.USER_NOT_FOUND,
                                "User with given email not found"
                        )
                );

        AuthFlowSession session = sessionRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ApiException(
                        HttpStatus.UNAUTHORIZED,
                        ErrorCode.SESSION_NOT_EXISTS,
                        "Session does not exists"
                ));

        if (!passwordEncoder.matches(sessionToken, session.getSessionTokenHash())) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.SESSION_NOT_EXISTS,
                    "Invalid session (token)"
            );
        }

        if (session.isExpired()) {
            sessionRepository.delete(session);
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.SESSION_EXPIRED,
                    "Session expired"
            );
        }

        if (!session.isVerified()) {
            throw new ApiException(
                    HttpStatus.FORBIDDEN,
                    ErrorCode.EMAIL_NOT_VERIFIED,
                    "Email not verified"
            );
        }

        if (!passwordValidator.isValid(request.getNewPassword())) {
            throw new ApiException(
                    HttpStatus.BAD_REQUEST,
                    ErrorCode.BAD_PASSWORD,
                    "Password does not meet the requirements"
            );
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        sessionRepository.delete(session);

        List<AuthSession> sessions = authSessionRepository.findAllByUserId(user.getId());
        for (AuthSession s : sessions) {
            if (!s.getDeviceId().equals(request.getDeviceId())) {
                authSessionRepository.delete(s);
            }
        }
    }
}