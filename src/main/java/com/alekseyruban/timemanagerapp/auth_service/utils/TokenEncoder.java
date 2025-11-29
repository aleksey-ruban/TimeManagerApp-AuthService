package com.alekseyruban.timemanagerapp.auth_service.utils;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class TokenEncoder {

    private static final SecureRandom random = new SecureRandom();

    public String hash(String token) {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        String saltB64 = Base64.getEncoder().encodeToString(salt);

        String hash = hashWithSalt(token, salt);

        return saltB64 + ":" + hash;
    }

    public boolean matches(String rawToken, String stored) {
        if (stored == null || !stored.contains(":")) return false;

        String[] parts = stored.split(":");
        String saltB64 = parts[0];
        String hash = parts[1];

        byte[] salt = Base64.getDecoder().decode(saltB64);
        String rawHash = hashWithSalt(rawToken, salt);

        return rawHash.equals(hash);
    }

    private String hashWithSalt(String token, byte[] salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(salt);
            byte[] hashedBytes = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }
}