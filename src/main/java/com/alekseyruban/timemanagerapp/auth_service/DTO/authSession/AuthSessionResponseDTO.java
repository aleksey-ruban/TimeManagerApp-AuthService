package com.alekseyruban.timemanagerapp.auth_service.DTO.authSession;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.Instant;

@Data
@AllArgsConstructor
public class AuthSessionResponseDTO {
    private Long sessionId;
    private String deviceModel;
    private Instant createdAt;
    private Instant lastUsedAt;
}
