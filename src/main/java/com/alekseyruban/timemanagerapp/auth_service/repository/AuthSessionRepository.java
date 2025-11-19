package com.alekseyruban.timemanagerapp.auth_service.repository;

import com.alekseyruban.timemanagerapp.auth_service.entity.AuthSession;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuthSessionRepository  extends JpaRepository<AuthSession, Long> {
    Optional<AuthSession> findByUserIdAndDeviceId(Long userId, UUID deviceId);
    Optional<AuthSession> findBySessionId(Long sessionId);
    List<AuthSession> findAllByUserId(Long userId);

    @Transactional
    @Modifying
    @Query("DELETE FROM AuthSession s WHERE s.user.id = :userId AND s.sessionId <> :sessionId")
    void deleteAllByUserIdAndSessionIdNot(@Param("userId") Long userId, @Param("sessionId") Long sessionId);

    @Transactional
    @Modifying
    @Query("DELETE FROM AuthSession s WHERE s.user.id = :userId")
    void deleteAllByUserId(@Param("userId") Long userId);
}
