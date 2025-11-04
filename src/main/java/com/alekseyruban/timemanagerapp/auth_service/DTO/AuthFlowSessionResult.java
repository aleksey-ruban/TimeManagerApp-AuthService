package com.alekseyruban.timemanagerapp.auth_service.DTO;

import lombok.*;

import java.time.Instant;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthFlowSessionResult {
    private String sessionToken;
    private Instant expiresAt;
}
