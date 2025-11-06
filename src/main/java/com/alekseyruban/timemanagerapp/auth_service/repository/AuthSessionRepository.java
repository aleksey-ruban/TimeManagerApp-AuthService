package com.alekseyruban.timemanagerapp.auth_service.repository;

import com.alekseyruban.timemanagerapp.auth_service.entity.AuthSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuthSessionRepository  extends JpaRepository<AuthSession, Long> {
    Optional<AuthSession> findByUserIdAndDeviceId(Long userId, UUID deviceId);
    Optional<AuthSession> findBySessionId(Long sessionId);
    List<AuthSession> findAllByUserId(Long userId);
}
