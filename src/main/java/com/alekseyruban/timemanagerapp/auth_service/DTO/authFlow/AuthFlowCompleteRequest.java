package com.alekseyruban.timemanagerapp.auth_service.DTO.authFlow;

import com.alekseyruban.timemanagerapp.auth_service.config.TrimStringDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AuthFlowCompleteRequest {
    @NotBlank
    @JsonDeserialize(using = TrimStringDeserializer.class)
    private String email;

    @NotBlank
    @JsonDeserialize(using = TrimStringDeserializer.class)
    private String firstName;

    @NotBlank
    private String password;
}
