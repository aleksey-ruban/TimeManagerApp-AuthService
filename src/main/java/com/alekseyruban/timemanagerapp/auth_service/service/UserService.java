package com.alekseyruban.timemanagerapp.auth_service.service;

import com.alekseyruban.timemanagerapp.auth_service.DTO.userOperations.UserResponseDTO;
import com.alekseyruban.timemanagerapp.auth_service.entity.AuthSession;
import com.alekseyruban.timemanagerapp.auth_service.entity.User;
import com.alekseyruban.timemanagerapp.auth_service.exception.ApiException;
import com.alekseyruban.timemanagerapp.auth_service.exception.ErrorCode;
import com.alekseyruban.timemanagerapp.auth_service.utils.TextValidator;
import com.alekseyruban.timemanagerapp.auth_service.repository.AuthSessionRepository;
import com.alekseyruban.timemanagerapp.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final AuthSessionRepository sessionRepository;
    private final TextValidator textValidator;

    private User getUserBySession(Long sessionId) {
        AuthSession session = sessionRepository.findBySessionId(sessionId)
                .orElseThrow(
                        () -> new ApiException(
                                HttpStatus.UNAUTHORIZED,
                                ErrorCode.SESSION_NOT_EXISTS,
                                "Session not exists"
                        )
                );
        return userRepository.findByEmailAndDeletedFalse(session.getUser().getEmail())
                .orElseThrow(
                        () -> new ApiException(
                                HttpStatus.NOT_FOUND,
                                ErrorCode.USER_NOT_FOUND,
                                "User not found"
                        )
                );
    }

    public UserResponseDTO getUser(Long sessionId) {
        User user = getUserBySession(sessionId);
        return new UserResponseDTO(user.getFirstName(), user.getEmail());
    }

    public void updateFirstName(Long sessionId, String newFirstName) {
        User user = getUserBySession(sessionId);
        if (!textValidator.isValidName(newFirstName)) {
            throw new ApiException(
                    HttpStatus.BAD_REQUEST,
                    ErrorCode.BAD_NAME,
                    "Name does not meet the requirements"
            );
        }

        user.setFirstName(newFirstName);
        userRepository.save(user);
    }

    public void softDeleteUser(Long sessionId) {
        User user = getUserBySession(sessionId);

        sessionRepository.deleteAllByUserId(user.getId());

        user.setDeleted(true);
        user.setDeletedAt(Instant.now());
        // TODO: Delete all user entities

        userRepository.save(user);
    }
}