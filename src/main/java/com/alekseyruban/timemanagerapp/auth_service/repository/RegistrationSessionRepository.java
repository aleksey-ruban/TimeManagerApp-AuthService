package com.alekseyruban.timemanagerapp.auth_service.repository;

import com.alekseyruban.timemanagerapp.auth_service.entity.AuthFlowSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RegistrationSessionRepository extends JpaRepository<AuthFlowSession, Long> {
    Optional<AuthFlowSession> findByEmail(String email);
    Optional<AuthFlowSession> findByEmailAndVerificationCodeHash(String email, String code);
}