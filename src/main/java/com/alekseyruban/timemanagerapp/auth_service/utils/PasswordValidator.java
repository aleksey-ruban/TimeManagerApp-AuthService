package com.alekseyruban.timemanagerapp.auth_service.utils;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Pattern;

@Service
public class PasswordValidator {

    @Value("${app-debug:false}")
    private boolean debug;

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 64;

    private static final Pattern COMPLEXITY_PATTERN = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-–={}:;\"'<>?,./]).+$"
    );

    private static final List<String> COMMON_PASSWORDS = List.of(
            "password", "12345678", "qwerty", "letmein", "admin",
            "welcome", "iloveyou", "monkey", "abc123"
    );

    public boolean isValid(String password) {
        if (password == null || password.isBlank()) {
            return false;
        }

        if (password.contains(" ")) {
            return false;
        }

        if (debug) {
            return true;
        }

        if (password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
            return false;
        }

        if (!COMPLEXITY_PATTERN.matcher(password).matches()) {
            return false;
        }

        String lower = password.toLowerCase();
        return COMMON_PASSWORDS.stream().noneMatch(lower::contains);
    }
}