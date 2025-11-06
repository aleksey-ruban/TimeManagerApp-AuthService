package com.alekseyruban.timemanagerapp.auth_service.controller.v1;

import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowResetPasswordRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowSessionResult;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowStartRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowVerifyRequest;
import com.alekseyruban.timemanagerapp.auth_service.exception.ApiException;
import com.alekseyruban.timemanagerapp.auth_service.exception.ErrorCode;
import com.alekseyruban.timemanagerapp.auth_service.service.ResetPasswordService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth/password/reset")
public class ResetPasswordController {

    private final ResetPasswordService resetPasswordService;

    @PostMapping("/start")
    public ResponseEntity<?> start(@Valid @RequestBody AuthFlowStartRequest request,
                                   HttpServletResponse response) {

        AuthFlowSessionResult result =
                resetPasswordService.startResettingPassword(request);

        ResponseCookie cookie = ResponseCookie.from("AUTH_SESSION", result.getSessionToken())
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/api/v1/auth/password/reset")
                .maxAge(Duration.ofMinutes(15))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.ok(Map.of(
                "message", "Code sent by email",
                "expiresAt", result.getExpiresAt()
        ));
    }

    @PostMapping("/resend-code")
    public ResponseEntity<?> resendCode(
            @Valid @RequestBody AuthFlowStartRequest request,
            @CookieValue(value = "AUTH_SESSION", required = false) String sessionToken) {
        if (sessionToken == null) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.SESSION_NOT_EXISTS,
                    "Session token missing"
            );
        }

        resetPasswordService.resendCode(request, sessionToken);
        return ResponseEntity.ok(Map.of(
                "message", "Verification code resent to your email"
        ));
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verify(@Valid @RequestBody AuthFlowVerifyRequest request,
                                    @CookieValue(value = "AUTH_SESSION", required = false) String sessionToken) {
        if (sessionToken == null) throw new ApiException(
                HttpStatus.UNAUTHORIZED,
                ErrorCode.SESSION_NOT_EXISTS,
                "Session token missing"
        );
        resetPasswordService.verifyCode(request, sessionToken);
        return ResponseEntity.ok(Map.of(
                "message", "Email verified"
        ));
    }

    @PostMapping("/complete")
    public ResponseEntity<?> complete(@Valid @RequestBody AuthFlowResetPasswordRequest request,
                                      @CookieValue(value = "AUTH_SESSION", required = false) String sessionToken) {
        if (sessionToken == null) throw new ApiException(
                HttpStatus.UNAUTHORIZED,
                ErrorCode.SESSION_NOT_EXISTS,
                "Session token missing"
        );
        resetPasswordService.completeResettingPassword(
                request,
                sessionToken
        );

        ResponseCookie deleteCookie = ResponseCookie.from("AUTH_SESSION", "")
                .path("/api/v1/auth/password/reset")
                .maxAge(0)
                .build();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, deleteCookie.toString()).body(Map.of(
                "message", "New password accepted"
        ));
    }
}