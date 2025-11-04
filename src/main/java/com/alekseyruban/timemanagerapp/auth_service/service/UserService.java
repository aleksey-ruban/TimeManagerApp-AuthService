package com.alekseyruban.timemanagerapp.auth_service.service;

import com.alekseyruban.timemanagerapp.auth_service.entity.User;
import com.alekseyruban.timemanagerapp.auth_service.exception.ApiException;
import com.alekseyruban.timemanagerapp.auth_service.exception.ErrorCode;
import com.alekseyruban.timemanagerapp.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public User registerUser(String email, String firstName, String rawPassword) {
        if (userRepository.findByEmail(email).isPresent()) {
            throw new ApiException(
                HttpStatus.CONFLICT,
                ErrorCode.EMAIL_ALREADY_REGISTERED,
                "User with email already exists"
            );
        }

        User user = User.builder()
                .email(email)
                .firstName(firstName)
                .password(passwordEncoder.encode(rawPassword))
                .build();

        return userRepository.save(user);
    }

    public User updateFirstName(String email, String newFirstName) {
        User user = userRepository.findByEmailAndDeletedFalse(email)
                .orElseThrow(
                        () -> new ApiException(
                            HttpStatus.NOT_FOUND,
                            ErrorCode.USER_NOT_FOUND,
                            "User not found"
                        )
                );
        user.setFirstName(newFirstName);
        return userRepository.save(user);
    }

    public void softDeleteUser(String email) {
        User user = userRepository.findByEmailAndDeletedFalse(email)
                .orElseThrow(
                        () -> new ApiException(
                            HttpStatus.NOT_FOUND,
                            ErrorCode.USER_NOT_FOUND,
                            "User not found"
                        )
                );
        user.setDeleted(true);
        user.setDeletedAt(Instant.now());
        userRepository.save(user);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmailAndDeletedFalse(email);
    }
}