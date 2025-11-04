package com.alekseyruban.timemanagerapp.auth_service.DTO;

import lombok.Data;

@Data
public class AuthFlowVerifyRequest {
    private String email;
    private String code;
}
