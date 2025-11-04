package com.alekseyruban.timemanagerapp.auth_service.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class ApiException extends RuntimeException {
    private final HttpStatus status;
    private final ErrorCode code;

    public ApiException(HttpStatus status, ErrorCode code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }
}