package com.alekseyruban.timemanagerapp.auth_service.DTO.userOperations;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserResponseDTO {
    private String firstName;
    private String email;
}
