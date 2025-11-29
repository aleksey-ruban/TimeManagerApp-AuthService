package com.alekseyruban.timemanagerapp.auth_service.DTO.userOperations;

import com.alekseyruban.timemanagerapp.auth_service.utils.TrimStringDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class NewNameRequest {
    @NotBlank
    @JsonDeserialize(using = TrimStringDeserializer.class)
    private String name;
}
