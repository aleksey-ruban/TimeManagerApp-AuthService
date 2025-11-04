package com.alekseyruban.timemanagerapp.auth_service.DTO;

import lombok.Data;

@Data
public class AuthFlowStartRequest {
    private String email;
    private String local;
}