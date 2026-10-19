package com.fptaptech.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    @Value("${app.mail.smtp-enabled:false}")
    private boolean smtpEnabled;

    @Value("${app.mail.host:localhost}")
    private String smtpHost;

    @Value("${app.mail.port:1025}")
    private int smtpPort;

    @Value("${app.mail.from:no-reply@fptaptech.edu.vn}")
    private String fromEmail;

    @Value("${app.security.base-url:http://localhost:8080}")
    private String baseUrl;

    public void sendVerificationEmail(String toEmail, String token) {
        String link = baseUrl + "/verify-email?token=" + token;
        String subject = "Xác minh tài khoản FPT Aptech";
        String body = "Xin chào,\n\nVui lòng bấm vào liên kết sau để kích hoạt tài khoản của bạn:\n"
                + link + "\n\nLiên kết có hiệu lực trong 24 giờ.\n\nTrân trọng,\nFPT Aptech Portal";
        sendEmail(toEmail, subject, body);
    }

    public void sendPasswordResetEmail(String toEmail, String token) {
        String link = baseUrl + "/password/reset?token=" + token;
        String subject = "Đặt lại mật khẩu FPT Aptech";
        String body = "Xin chào,\n\nBạn vừa yêu cầu đặt lại mật khẩu. Vui lòng bấm vào liên kết sau:\n"
                + link + "\n\nLiên kết có hiệu lực trong 30 phút và chỉ sử dụng một lần.\n\nTrân trọng,\nFPT Aptech Portal";
        sendEmail(toEmail, subject, body);
    }

    public void sendInvitationEmail(String toEmail, String token, String role) {
        String link = baseUrl + "/invite/accept?token=" + token;
        String subject = "Lời mời tham gia Cổng tài khoản FPT Aptech (" + role + ")";
        String body = "Xin chào,\n\nBạn đã được mời tham gia hệ thống với vai trò " + role
                + ".\nVui lòng bấm vào liên kết sau để thiết lập mật khẩu và kích hoạt tài khoản:\n"
                + link + "\n\nTrân trọng,\nFPT Aptech Portal";
        sendEmail(toEmail, subject, body);
    }

    public void sendEmail(String to, String subject, String content) {
        log.info("Sending email to {}: Subject: {}\nContent:\n{}", to, subject, content);
        if (!smtpEnabled) {
            return;
        }

        try (Socket socket = new Socket(smtpHost, smtpPort);
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
             PrintWriter writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true)) {

            reader.readLine(); // 220 banner
            writer.println("HELO localhost");
            reader.readLine(); // 250 OK

            writer.println("MAIL FROM:<" + fromEmail + ">");
            reader.readLine(); // 250 OK

            writer.println("RCPT TO:<" + to + ">");
            reader.readLine(); // 250 OK

            writer.println("DATA");
            reader.readLine(); // 354 Start mail input

            writer.println("From: " + fromEmail);
            writer.println("To: " + to);
            writer.println("Subject: " + subject);
            writer.println("Content-Type: text/plain; charset=UTF-8");
            writer.println();
            writer.println(content);
            writer.println(".");
            reader.readLine(); // 250 OK

            writer.println("QUIT");
            reader.readLine(); // 221 Bye
        } catch (Exception e) {
            log.warn("Could not send email via SMTP {}:{}: {}", smtpHost, smtpPort, e.getMessage());
        }
    }
}
