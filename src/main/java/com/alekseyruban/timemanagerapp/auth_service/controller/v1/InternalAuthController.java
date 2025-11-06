package com.alekseyruban.timemanagerapp.auth_service.controller.v1;

import com.alekseyruban.timemanagerapp.auth_service.DTO.authSession.TokenValidationRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.authSession.TokenValidationResponse;
import com.alekseyruban.timemanagerapp.auth_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/internal")
public class InternalAuthController {

    private final AuthService authService;

    @PostMapping("/validate-access-token")
    public TokenValidationResponse validateAccessToken(@Valid @RequestBody TokenValidationRequest request) {
        boolean valid = authService.checkAccessTokenValid(request);
        return new TokenValidationResponse(valid);
    }
}