package com.alekseyruban.timemanagerapp.auth_service.DTO.authSession;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class TokenValidationRequest {
    @NotNull
    private Long sessionId;

    @NotBlank
    private String token;
}
