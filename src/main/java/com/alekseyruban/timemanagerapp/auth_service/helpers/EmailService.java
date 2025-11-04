package com.alekseyruban.timemanagerapp.auth_service.helpers;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class EmailService {

    @Value("${app-debug:false}")
    private boolean debug;

    private final JavaMailSender mailSender;

    private static final String SUBJECT_EN = "Time Manager — Verification Code";
    private static final String SUBJECT_RU = "Time Manager — Код подтверждения";

    private static final Set<String> SUPPORTED_LOCALES = Set.of("en", "ru");

    public void sendVerificationCode(String to, String code, String locale) {
        sendEmail(to, code, false, locale);
    }

    public void resendVerificationCode(String to, String code, String locale) {
        sendEmail(to, code, true, locale);
    }

    private void sendEmail(String to, String code, boolean isResend, String locale) {
        // Если неизвестная локаль, используем en
        String lang = SUPPORTED_LOCALES.contains(locale) ? locale : "en";

        if (debug) {
            System.out.println("[DEBUG] " + (isResend ? "Resend" : "Send") +
                    " code=" + code + " email=" + to + " locale=" + lang);
            return;
        }

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(getSubject(lang));
        message.setText(buildMessageBody(code, isResend, lang));

        mailSender.send(message);
    }

    private String getSubject(String locale) {
        return switch (locale) {
            case "ru" -> SUBJECT_RU;
            default -> SUBJECT_EN;
        };
    }

    private String buildMessageBody(String code, boolean isResend, String locale) {
        if ("ru".equals(locale)) {
            String greeting = "Здравствуйте!";
            String action = isResend ? "Вы запросили повторную отправку кода."
                    : "Вы начали процесс регистрации.";
            return String.format(
                    "%s%n%n%s%n%nВаш код подтверждения: %s%n%n" +
                            "Он действителен 15 минут.%nЕсли это были не вы — просто проигнорируйте письмо.%n%nС уважением,%nTime Manager",
                    greeting, action, code
            );
        } else {
            String greeting = "Hello!";
            String action = isResend ? "You requested to resend the code."
                    : "You started the registration process.";
            return String.format(
                    "%s%n%n%s%n%nYour verification code: %s%n%n" +
                            "It is valid for 15 minutes. If this wasn't you, just ignore this email.%n%nBest regards,%nTime Manager",
                    greeting, action, code
            );
        }
    }
}