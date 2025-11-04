package com.alekseyruban.timemanagerapp.auth_service.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Duration;
import java.time.Instant;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthFlowSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String sessionTokenHash;

    @Column(nullable = false)
    private String verificationCodeHash;

    @Column(nullable = false)
    private boolean verified = false;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @CreationTimestamp
    @Column(nullable = false)
    private Instant lastCodeSentAt;

    @Column(nullable = false)
    private Instant expiresAt;

    @Transient
    public boolean isExpired() {
        return expiresAt.isBefore(Instant.now());
    }

    @Transient
    public boolean isCreatedWithinOneMinute() {
        return Duration.between(createdAt, Instant.now()).toSeconds() < 60;
    }

    @Transient
    public boolean isCodeSentWithinOneMinute() {
        return Duration.between(lastCodeSentAt, Instant.now()).toSeconds() < 60;
    }
}