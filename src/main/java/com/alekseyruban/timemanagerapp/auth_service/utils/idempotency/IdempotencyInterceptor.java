package com.alekseyruban.timemanagerapp.auth_service.utils.idempotency;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class IdempotencyInterceptor implements HandlerInterceptor {

    private static final String IDEMPOTENCY_HEADER = "Idempotency-Key";

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    @Override
    public boolean preHandle(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler
    ) throws Exception {

        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        Idempotent idempotent = handlerMethod.getMethodAnnotation(Idempotent.class);
        if (idempotent == null) {
            return true;
        }

        String key = request.getHeader(IDEMPOTENCY_HEADER);
        if (key == null || key.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Missing Idempotency-Key header"
            );
        }

        String redisKey = buildRedisKey(request, key);

        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(response);

        String cached = redisTemplate.opsForValue().get(redisKey);
        if (cached != null && !cached.equals("IN_PROGRESS")) {
            CachedResponse cachedResponse =
                    objectMapper.readValue(cached, CachedResponse.class);

            byte[] body = cachedResponse.getBody();

            response.setStatus(cachedResponse.getStatus());
            response.setContentType("application/json");
            cachedResponse.getHeaders().forEach(response::setHeader);
            response.getOutputStream().write(body);
            return false;
        }

        Boolean locked = redisTemplate.opsForValue()
                .setIfAbsent(
                        redisKey,
                        "IN_PROGRESS",
                        Duration.ofSeconds(idempotent.lockSeconds())
                );

        if (Boolean.FALSE.equals(locked)) {
            response.sendError(409, "Request is already in progress");
            return false;
        }

        request.setAttribute("redisKey", redisKey);
        request.setAttribute("wrappedResponse", wrappedResponse);

        return true;
    }


    @Override
    public void afterCompletion(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler,
            Exception ex
    ) throws Exception {

        Object redisKeyObj = request.getAttribute("redisKey");
        Object wrappedResponseObj = request.getAttribute("wrappedResponse");

        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return;
        }
        Idempotent idempotent = handlerMethod.getMethodAnnotation(Idempotent.class);

        if (redisKeyObj == null || idempotent == null || wrappedResponseObj == null) {
            return;
        }

        String redisKey = (String) redisKeyObj;
        ContentCachingResponseWrapper wrappedResponse = (ContentCachingResponseWrapper) response;

        if (ex != null) {
            redisTemplate.delete(redisKey);
            return;
        }

        byte[] responseBody = wrappedResponse.getContentAsByteArray();

        CachedResponse cachedResponse = new CachedResponse(
                wrappedResponse.getStatus(),
                responseBody,
                extractHeaders(wrappedResponse)
        );

        redisTemplate.opsForValue().set(
                redisKey,
                objectMapper.writeValueAsString(cachedResponse),
                Duration.ofSeconds(idempotent.ttlSeconds())
        );

        wrappedResponse.copyBodyToResponse();
    }

    private String buildRedisKey(HttpServletRequest request, String key) {
        return "idempotency:" + request.getMethod() + ":" + request.getRequestURI() + ":" + key;
    }

    private Map<String, String> extractHeaders(HttpServletResponse response) {
        Map<String, String> headers = new HashMap<>();
        for (String name : response.getHeaderNames()) {
            headers.put(name, response.getHeader(name));
        }
        return headers;
    }
}