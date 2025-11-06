package com.alekseyruban.timemanagerapp.auth_service.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.List;

@Entity
@Table(name = "app_user")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AuthSession> sessions;

    @Column(nullable = false)
    private String firstName;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant registeredAt;

    @Column(nullable = false)
    private boolean deleted = false;

    @Column
    private Instant deletedAt;

}