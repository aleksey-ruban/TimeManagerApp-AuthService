package com.alekseyruban.timemanagerapp.auth_service.DTO.authSession;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenValidationResponse {
    @NotNull
    private Boolean valid;
}
