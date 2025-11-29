package com.alekseyruban.timemanagerapp.auth_service.DTO.authSession;

import com.alekseyruban.timemanagerapp.auth_service.utils.TrimStringDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.UUID;

@Data
public class LoginRequest {
    @NotBlank
    @JsonDeserialize(using = TrimStringDeserializer.class)
    private String email;

    @NotBlank
    private String password;

    @NotNull
    private UUID deviceId;

    @NotBlank
    @JsonDeserialize(using = TrimStringDeserializer.class)
    private String deviceModel;

    @NotNull
    private Boolean isAutomatic;
}
