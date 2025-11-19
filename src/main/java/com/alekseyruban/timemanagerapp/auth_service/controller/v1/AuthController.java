package com.alekseyruban.timemanagerapp.auth_service.controller.v1;

import com.alekseyruban.timemanagerapp.auth_service.DTO.authSession.*;
import com.alekseyruban.timemanagerapp.auth_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-tokens")
    public ResponseEntity<AuthResponse> resetTokens(@Valid @RequestBody RefreshTokensRequest request) {
        AuthResponse response = authService.refreshTokens(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout/device")
    public ResponseEntity<?> logoutSpecificDevice(@Valid @RequestBody LogoutDeviceRequest request) {
        authService.logoutSpecificDevice(request.getSessionId());
        return ResponseEntity.ok(Map.of(
                "message", "Logout successfully"
        ));
    }

    @PostMapping("/logout/others")
    public ResponseEntity<?> logoutAllDevicesExceptCurrent(@RequestHeader("X-Session-Id") Long sessionId) {
        authService.logoutAllDevicesExceptCurrent(sessionId);
        return ResponseEntity.ok(Map.of(
                "message", "Logout successfully"
        ));
    }

    @GetMapping("/sessions")
    public ResponseEntity<UserSessionsResponseDTO> getUserSessions(
            @RequestHeader("X-Session-Id") Long sessionId
    ) {
        UserSessionsResponseDTO response = authService.getUserSessions(sessionId);
        return ResponseEntity.ok(response);
    }
}