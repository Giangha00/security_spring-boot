package com.fptaptech.auth.service;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.PasswordHistory;
import com.fptaptech.auth.repository.PasswordHistoryRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
public class PasswordPolicyValidator {

    private final PasswordEncoder passwordEncoder;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final Set<String> commonPasswords = new HashSet<>();

    public PasswordPolicyValidator(PasswordEncoder passwordEncoder,
                                   PasswordHistoryRepository passwordHistoryRepository) {
        this.passwordEncoder = passwordEncoder;
        this.passwordHistoryRepository = passwordHistoryRepository;
    }

    @PostConstruct
    void initCommonPasswords() {
        try {
            ClassPathResource resource = new ClassPathResource("common-passwords.txt");
            if (resource.exists()) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        String trimmed = line.trim().toLowerCase(Locale.ROOT);
                        if (!trimmed.isEmpty()) {
                            commonPasswords.add(trimmed);
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    public void validate(String rawPassword, String username, String email, AppUser user) {
        if (rawPassword == null || rawPassword.length() < 12) {
            throw new PasswordPolicyException("Mật khẩu phải dài tối thiểu 12 ký tự");
        }

        String lowerPassword = rawPassword.toLowerCase(Locale.ROOT);

        if (username != null && !username.isBlank()) {
            String lowerUsername = username.trim().toLowerCase(Locale.ROOT);
            if (lowerUsername.length() >= 3 && lowerPassword.contains(lowerUsername)) {
                throw new PasswordPolicyException("Mật khẩu không được chứa username");
            }
        }

        if (email != null && !email.isBlank()) {
            String lowerEmail = email.trim().toLowerCase(Locale.ROOT);
            String localPart = lowerEmail.contains("@") ? lowerEmail.split("@")[0] : lowerEmail;
            if (lowerPassword.contains(lowerEmail) || (localPart.length() >= 3 && lowerPassword.contains(localPart))) {
                throw new PasswordPolicyException("Mật khẩu không được chứa email");
            }
        }

        if (commonPasswords.contains(lowerPassword)) {
            throw new PasswordPolicyException("Mật khẩu nằm trong danh sách mật khẩu phổ biến, vui lòng chọn mật khẩu khác");
        }

        if (user != null && user.getId() != null) {
            List<PasswordHistory> recentHistories = passwordHistoryRepository.findTop5ByUserOrderByCreatedAtDesc(user);
            for (PasswordHistory history : recentHistories) {
                if (passwordEncoder.matches(rawPassword, history.getPasswordHash())) {
                    throw new PasswordPolicyException("Mật khẩu mới không được trùng với bất kỳ mật khẩu nào trong 5 mật khẩu gần nhất");
                }
            }
        }
    }
}
