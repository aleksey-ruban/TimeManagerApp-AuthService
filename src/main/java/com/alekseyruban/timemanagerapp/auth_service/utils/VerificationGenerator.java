package com.alekseyruban.timemanagerapp.auth_service.utils;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.UUID;

@Component
public class VerificationGenerator {

    private final SecureRandom random = new SecureRandom();

    public String generateEmailCode() {
        return String.format("%06d", random.nextInt(999_999));
    }

    public String generateSessionToken() {
        return UUID.randomUUID().toString();
    }

}