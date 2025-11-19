package com.alekseyruban.timemanagerapp.auth_service.DTO.authSession;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class UserSessionsResponseDTO {
    private Long currentSessionId;
    private List<AuthSessionResponseDTO> sessions;
}
