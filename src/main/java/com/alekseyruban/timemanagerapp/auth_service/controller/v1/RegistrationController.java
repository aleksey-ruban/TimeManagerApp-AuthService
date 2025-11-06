package com.alekseyruban.timemanagerapp.auth_service.controller.v1;

import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowCompleteRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowStartRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowVerifyRequest;
import com.alekseyruban.timemanagerapp.auth_service.exception.ApiException;
import com.alekseyruban.timemanagerapp.auth_service.exception.ErrorCode;
import com.alekseyruban.timemanagerapp.auth_service.service.RegistrationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth/registration")
public class RegistrationController {

    private final RegistrationService registrationService;

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

        registrationService.resendCode(request, sessionToken);
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
        registrationService.verifyCode(request, sessionToken);
        return ResponseEntity.ok(Map.of(
                "message", "Email verified"
        ));
    }

    @PostMapping("/complete")
    public ResponseEntity<?> complete(@Valid @RequestBody AuthFlowCompleteRequest request,
                                      @CookieValue(value = "AUTH_SESSION", required = false) String sessionToken) {
        if (sessionToken == null) throw new ApiException(
                HttpStatus.UNAUTHORIZED,
                ErrorCode.SESSION_NOT_EXISTS,
                "Session token missing"
        );
        registrationService.completeRegistration(
                request,
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