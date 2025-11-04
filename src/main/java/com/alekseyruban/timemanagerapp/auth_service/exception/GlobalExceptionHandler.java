package com.alekseyruban.timemanagerapp.auth_service.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<?> handleApiException(ApiException ex) {
        return ResponseEntity
                .status(ex.getStatus())
                .body(Map.of(
                        "error", ex.getMessage(),
                        "status", ex.getStatus().value(),
                        "timestamp", LocalDateTime.now()
                ));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleUnexpected(Exception ex) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                        "error", "Unexpected error: " + ex.getMessage(),
                        "status", 500,
                        "timestamp", LocalDateTime.now()
                ));
    }
}