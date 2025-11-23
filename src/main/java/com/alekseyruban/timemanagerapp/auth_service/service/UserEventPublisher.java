package com.alekseyruban.timemanagerapp.auth_service.service;

import com.alekseyruban.timemanagerapp.auth_service.DTO.rabbit.UserCreatedEvent;
import com.alekseyruban.timemanagerapp.auth_service.config.RabbitConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserEventPublisher {

    private final RabbitTemplate rabbitTemplate;

    public void publishUserCreated(UserCreatedEvent event) {
        rabbitTemplate.convertAndSend(
                RabbitConfig.USER_EVENTS_EXCHANGE,
                RabbitConfig.USER_CREATED_KEY,
                event
        );
    }
}
