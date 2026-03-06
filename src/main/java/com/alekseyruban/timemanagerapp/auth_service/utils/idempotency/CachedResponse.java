package com.alekseyruban.timemanagerapp.auth_service.utils.idempotency;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CachedResponse {
    private int status;
    private byte[] body;
    private Map<String, String> headers;
}