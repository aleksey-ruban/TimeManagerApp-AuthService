package com.alekseyruban.timemanagerapp.auth_service.utils.idempotency;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Idempotent {

    /**
     * TTL for saved results
     */
    long ttlSeconds() default 21600;

    /**
     * TTL for IN_PROGRESS lock
     */
    long lockSeconds() default 30;
}