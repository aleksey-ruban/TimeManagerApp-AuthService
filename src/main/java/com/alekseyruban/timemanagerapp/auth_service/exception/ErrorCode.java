package com.alekseyruban.timemanagerapp.auth_service.exception;

public enum ErrorCode {
    SESSION_NOT_EXISTS,
    SESSION_EXPIRED,
    INVALID_CODE,
    EMAIL_ALREADY_REGISTERED,
    EMAIL_IN_PROGRESS,
    EMAIL_NOT_VERIFIED,
    EMAIL_COOL_DOWN,
    EMAIL_ALREADY_VERIFIED,
    INVALID_EMAIL_DOMAIN,
    USER_NOT_FOUND,
    INTERNAL_ERROR
}