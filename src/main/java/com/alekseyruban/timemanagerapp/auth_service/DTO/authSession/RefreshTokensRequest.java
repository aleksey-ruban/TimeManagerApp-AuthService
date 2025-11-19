package com.alekseyruban.timemanagerapp.auth_service.DTO.authSession;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RefreshTokensRequest {
    @NotBlank
    private String refreshToken;
}
