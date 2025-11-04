package com.alekseyruban.timemanagerapp.auth_service.controller;

import com.alekseyruban.timemanagerapp.auth_service.DTO.AuthFlowCompleteRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.AuthFlowSessionResult;
import com.alekseyruban.timemanagerapp.auth_service.DTO.AuthFlowStartRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.AuthFlowVerifyRequest;
import com.alekseyruban.timemanagerapp.auth_service.exception.ApiException;
import com.alekseyruban.timemanagerapp.auth_service.exception.ErrorCode;
import com.alekseyruban.timemanagerapp.auth_service.service.RegistrationService;
import jakarta.servlet.http.HttpServletResponse;
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
@RequestMapping("/registration")
public class RegistrationController {

    private final RegistrationService registrationService;

    @PostMapping("/start")
    public ResponseEntity<?> start(@RequestBody AuthFlowStartRequest request,
                                   HttpServletResponse response) {

        AuthFlowSessionResult result =
                registrationService.startRegistration(request);

        ResponseCookie cookie = ResponseCookie.from("AUTH_SESSION", result.getSessionToken())
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/registration")
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
            @RequestBody AuthFlowStartRequest request,
            @CookieValue(value = "AUTH_SESSION", required = false) String sessionToken) {
        if (sessionToken == null) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.SESSION_NOT_EXISTS,
                    "Session token missing"
            );
        }

        registrationService.resendCode(request, sessionToken);
        return ResponseEntity.ok(Map.of(
                "message", "Verification code resent to your email"
        ));
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody AuthFlowVerifyRequest request,
                                    @CookieValue(value = "AUTH_SESSION", required = false) String sessionToken) {
        if (sessionToken == null) throw new ApiException(
                HttpStatus.UNAUTHORIZED,
                ErrorCode.SESSION_NOT_EXISTS,
                "Session token missing"
        );
        registrationService.verifyCode(request.getEmail(), request.getCode(), sessionToken);
        return ResponseEntity.ok(Map.of(
                "message", "Email verified"
        ));
    }

    @PostMapping("/complete")
    public ResponseEntity<?> complete(@RequestBody AuthFlowCompleteRequest request,
                                      @CookieValue(value = "AUTH_SESSION", required = false) String sessionToken) {
        if (sessionToken == null) throw new ApiException(
                HttpStatus.UNAUTHORIZED,
                ErrorCode.SESSION_NOT_EXISTS,
                "Session token missing"
        );
        registrationService.completeRegistration(
                request.getEmail(),
                request.getFirstName(),
                request.getPassword(),
                sessionToken
        );

        ResponseCookie deleteCookie = ResponseCookie.from("AUTH_SESSION", "")
                .path("/registration")
                .maxAge(0)
                .build();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, deleteCookie.toString()).body(Map.of(
                "message", "Registration completed"
        ));
    }
}