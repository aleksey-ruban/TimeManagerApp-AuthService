package com.alekseyruban.timemanagerapp.auth_service.utils;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Pattern;

@Service
public class TextValidator {

    private static final int MIN_LENGTH = 2;
    private static final int MAX_LENGTH = 50;

    private static final Pattern BASIC_PATTERN = Pattern.compile("^[\\p{L}\\p{N}\\s\\-']+$");

    private static final List<String> FORBIDDEN_WORDS = List.of(
            "admin", "root", "test"
    );

    public boolean isValidName(String text) {
        return isValidText(text, MIN_LENGTH, MAX_LENGTH, false);
    }

    public boolean isValidCategory(String text) {
        return isValidText(text, 1, 30, true);
    }

    public boolean isValidText(String text, int minLength, int maxLength, boolean allowNumbers) {
        if (text == null || text.isBlank()) {
            return false;
        }

        String trimmed = text.trim();

        if (trimmed.length() < minLength || trimmed.length() > maxLength) {
            return false;
        }

        if (!BASIC_PATTERN.matcher(trimmed).matches()) {
            return false;
        }

        if (!allowNumbers && trimmed.matches(".*\\p{N}.*")) {
            return false;
        }

        String lower = trimmed.toLowerCase();
        return FORBIDDEN_WORDS.stream().noneMatch(lower::contains);
    }
}