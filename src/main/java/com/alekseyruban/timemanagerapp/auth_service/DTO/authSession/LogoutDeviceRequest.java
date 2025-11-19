package com.alekseyruban.timemanagerapp.auth_service.DTO.authSession;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class LogoutDeviceRequest {
    @NotNull
    private Long sessionId;
}
