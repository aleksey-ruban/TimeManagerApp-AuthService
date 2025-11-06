package com.alekseyruban.timemanagerapp.auth_service.controller.v1;

import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowSessionResult;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow.AuthFlowStartRequest;
import com.alekseyruban.timemanagerapp.auth_service.service.RegistrationService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthFlowController {

    private final RegistrationService registrationService;

    @PostMapping("/start")
    public ResponseEntity<?> start(@Valid @RequestBody AuthFlowStartRequest request,
                                   HttpServletResponse response) {

        String email = request.getEmail();

        if (!registrationService.userExists(email)) {
            AuthFlowSessionResult result =
                    registrationService.startRegistration(request);

            ResponseCookie cookie = ResponseCookie.from("AUTH_SESSION", result.getSessionToken())
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("Strict")
                    .path("/api/v1/auth/registration")
                    .maxAge(Duration.ofMinutes(15))
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

            return ResponseEntity.ok(Map.of(
                    "action", "registration",
                    "message", "Code sent by email",
                    "expiresAt", result.getExpiresAt()
            ));
        } else {
            return ResponseEntity.ok(Map.of(
                    "action", "login",
                    "message", "Ready to login"
                    )
            );
        }
    }
}