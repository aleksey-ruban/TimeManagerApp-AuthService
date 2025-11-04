package com.alekseyruban.timemanagerapp.auth_service.DTO;

import lombok.Data;

@Data
public class AuthFlowCompleteRequest {
    private String email;
    private String firstName;
    private String password;
}
