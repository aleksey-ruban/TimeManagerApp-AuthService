package com.alekseyruban.timemanagerapp.auth_service;

import com.alekseyruban.timemanagerapp.auth_service.entity.AuthFlowSession;
import com.alekseyruban.timemanagerapp.auth_service.entity.AuthSession;
import com.alekseyruban.timemanagerapp.auth_service.exception.ApiException;
import com.alekseyruban.timemanagerapp.auth_service.helpers.JwtService;
import com.alekseyruban.timemanagerapp.auth_service.utils.PasswordValidator;
import com.alekseyruban.timemanagerapp.auth_service.utils.TextValidator;
import com.alekseyruban.timemanagerapp.auth_service.utils.TokenEncoder;
import com.alekseyruban.timemanagerapp.auth_service.utils.VerificationGenerator;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthUtilityTest {

    private static final String SECRET = "12345678901234567890123456789012";

    private final PasswordValidator passwordValidator = new PasswordValidator();
    private final TextValidator textValidator = new TextValidator();
    private final TokenEncoder tokenEncoder = new TokenEncoder();
    private final VerificationGenerator verificationGenerator = new VerificationGenerator();
    private final JwtService jwtService = new JwtService(SECRET);

    @ParameterizedTest
    @ValueSource(strings = {"Strong1!", "Another9@", "ValidPass123#", "Rocket9$X"})
    void passwordValidatorAcceptsStrongPasswords(String value) {
        ReflectionTestUtils.setField(passwordValidator, "debug", false);
        assertThat(passwordValidator.isValid(value)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "short1!", "nouppercase1!", "NOLOWERCASE1!", "NoDigit!!", "NoSpecial123", "with space 1!", "Password1!"})
    void passwordValidatorRejectsWeakPasswords(String value) {
        ReflectionTestUtils.setField(passwordValidator, "debug", false);
        assertThat(passwordValidator.isValid(value)).isFalse();
    }

    @Test
    void passwordValidatorAllowsAnyNonBlankPasswordInDebugMode() {
        ReflectionTestUtils.setField(passwordValidator, "debug", true);

        assertThat(passwordValidator.isValid("weak")).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"John", "Mary Jane", "Jean-Luc", "O'Connor"})
    void textValidatorAcceptsValidNames(String value) {
        assertThat(textValidator.isValidName(value)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "A", "John3", "admin", "Name!"})
    void textValidatorRejectsInvalidNames(String value) {
        assertThat(textValidator.isValidName(value)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"Work", "Work 2", "Learning"})
    void textValidatorAcceptsValidCategories(String value) {
        assertThat(textValidator.isValidCategory(value)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "test", "Category!", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"})
    void textValidatorRejectsInvalidCategories(String value) {
        assertThat(textValidator.isValidCategory(value)).isFalse();
    }

    @Test
    void tokenEncoderHashesAndMatchesOriginalToken() {
        String stored = tokenEncoder.hash("token");

        assertThat(tokenEncoder.matches("token", stored)).isTrue();
    }

    @Test
    void tokenEncoderGeneratesDifferentHashesForSameToken() {
        String first = tokenEncoder.hash("token");
        String second = tokenEncoder.hash("token");

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void tokenEncoderRejectsWrongToken() {
        String stored = tokenEncoder.hash("token");

        assertThat(tokenEncoder.matches("other", stored)).isFalse();
    }

    @Test
    void tokenEncoderRejectsMalformedStoredValue() {
        assertThat(tokenEncoder.matches("token", "bad")).isFalse();
    }

    @Test
    void verificationGeneratorProducesSixDigitCode() {
        String code = verificationGenerator.generateEmailCode();

        assertThat(code).matches("\\d{6}");
    }

    @Test
    void verificationGeneratorProducesUuidSessionToken() {
        String token = verificationGenerator.generateSessionToken();

        assertThat(token).matches("^[0-9a-f\\-]{36}$");
    }

    @Test
    void jwtServiceExtractsSessionIdFromRefreshToken() {
        String token = jwtService.generateRefreshToken(42L);

        assertThat(jwtService.extractSessionId(token)).isEqualTo(42L);
    }

    @Test
    void jwtServiceExtractsSessionIdFromAccessToken() {
        String token = jwtService.generateAccessToken(7L, 99L);

        assertThat(jwtService.extractSessionId(token)).isEqualTo(99L);
    }

    @Test
    void jwtServiceRejectsExpiredToken() {
        String token = Jwts.builder()
                .claim("sessionId", 77L)
                .expiration(java.util.Date.from(Instant.now().minusSeconds(5)))
                .signWith(io.jsonwebtoken.security.Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();

        assertThatThrownBy(() -> jwtService.extractSessionId(token))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void jwtServiceRejectsMalformedToken() {
        assertThatThrownBy(() -> jwtService.extractSessionId("not-a-jwt"))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void authSessionIsExpiredWhenExpirationInPast() {
        AuthSession session = AuthSession.builder()
                .expiresAt(Instant.now().minusSeconds(1))
                .build();

        assertThat(session.isExpired()).isTrue();
    }

    @Test
    void authSessionIsNotExpiredWhenExpirationInFuture() {
        AuthSession session = AuthSession.builder()
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        assertThat(session.isExpired()).isFalse();
    }

    @Test
    void authFlowSessionReportsExpiredWhenNeeded() {
        AuthFlowSession session = AuthFlowSession.builder()
                .expiresAt(Instant.now().minusSeconds(1))
                .createdAt(Instant.now().minusSeconds(120))
                .lastCodeSentAt(Instant.now().minusSeconds(120))
                .build();

        assertThat(session.isExpired()).isTrue();
    }

    @Test
    void authFlowSessionDetectsRecentCreation() {
        AuthFlowSession session = AuthFlowSession.builder()
                .createdAt(Instant.now().minusSeconds(30))
                .lastCodeSentAt(Instant.now().minusSeconds(90))
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        assertThat(session.isCreatedWithinOneMinute()).isTrue();
    }

    @Test
    void authFlowSessionDetectsRecentCodeSend() {
        AuthFlowSession session = AuthFlowSession.builder()
                .createdAt(Instant.now().minusSeconds(90))
                .lastCodeSentAt(Instant.now().minusSeconds(30))
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        assertThat(session.isCodeSentWithinOneMinute()).isTrue();
    }

    @Test
    void tokenEncoderStoresSaltAndHashSeparatedByColon() {
        String stored = tokenEncoder.hash("token");

        String[] parts = stored.split(":");
        assertThat(parts).hasSize(2);
        assertThat(Base64.getDecoder().decode(parts[0])).hasSize(16);
    }
}
