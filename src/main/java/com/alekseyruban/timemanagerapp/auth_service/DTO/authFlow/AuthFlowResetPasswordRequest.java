package com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow;

import com.alekseyruban.timemanagerapp.auth_service.config.TrimStringDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.UUID;

@Data
public class AuthFlowResetPasswordRequest {
    @NotBlank
    @JsonDeserialize(using = TrimStringDeserializer.class)
    private String email;

    @NotBlank
    private String newPassword;

    @NotNull
    private UUID deviceId;
}
