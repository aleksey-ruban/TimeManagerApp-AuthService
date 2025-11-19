package com.alekseyruban.timemanagerapp.auth_service.controller.v1;

import com.alekseyruban.timemanagerapp.auth_service.DTO.userOperations.NewNameRequest;
import com.alekseyruban.timemanagerapp.auth_service.DTO.userOperations.UserResponseDTO;
import com.alekseyruban.timemanagerapp.auth_service.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth/user")
public class UserController {

    private final UserService userService;

    @GetMapping
    public ResponseEntity<?> getUserProfile(
            @RequestHeader("X-Session-Id") Long sessionId
    ) {
        UserResponseDTO userDto = userService.getUser(sessionId);
        return ResponseEntity.ok(userDto);
    }

    @PatchMapping("/update-profile")
    public ResponseEntity<?> updateFirstName(
            @RequestHeader("X-Session-Id") Long sessionId,
            @Valid @RequestBody NewNameRequest request
    ) {
        userService.updateFirstName(sessionId, request.getName());
        return ResponseEntity.ok(Map.of(
                "message", "Profile successfully updated"
        ));
    }

    @DeleteMapping
    public ResponseEntity<?> softDeleteUser(
            @RequestHeader("X-Session-Id") Long sessionId
    ) {
        userService.softDeleteUser(sessionId);
        return ResponseEntity.ok(Map.of(
                "message", "User deleted"
        ));
    }
}
