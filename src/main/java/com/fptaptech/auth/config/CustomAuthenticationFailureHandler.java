package com.fptaptech.auth.config;

import com.fptaptech.auth.entity.AccountStatus;
import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.AuditEventType;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.AuditService;
import com.fptaptech.auth.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final UserRepository userRepository;
    private final AuditService auditService;
    private final PasswordEncoder dummyPasswordEncoder = new BCryptPasswordEncoder();
    private static final String DUMMY_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    public CustomAuthenticationFailureHandler(UserRepository userRepository, AuditService auditService) {
        this.userRepository = userRepository;
        this.auditService = auditService;
        setDefaultFailureUrl("/login?error");
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String username = request.getParameter("username");
        String rawPassword = request.getParameter("password");

        if (username != null && !username.isBlank()) {
            String normalized = UserService.normalize(username);
            AppUser user = userRepository.findByUsername(normalized)
                    .or(() -> userRepository.findByEmail(UserService.normalizeEmail(username)))
                    .orElse(null);

            if (user != null) {
                Instant now = Instant.now();
                if (user.getStatus() == AccountStatus.LOCKED && user.getLockedUntil() != null && user.getLockedUntil().isAfter(now)) {
                    // Still locked
                    auditService.record(AuditEventType.LOGIN_FAILURE, username, username, request, "Đăng nhập khi tài khoản đang bị khóa");
                } else {
                    if (user.getStatus() == AccountStatus.LOCKED && user.getLockedUntil() != null && user.getLockedUntil().isBefore(now)) {
                        user.setStatus(AccountStatus.ACTIVE);
                        user.setFailedLoginCount(0);
                        user.setLockedUntil(null);
                        user.setFirstFailedLoginAt(null);
                    }

                    if (user.getFirstFailedLoginAt() == null || Duration.between(user.getFirstFailedLoginAt(), now).toMinutes() >= 15) {
                        user.setFirstFailedLoginAt(now);
                        user.setFailedLoginCount(1);
                    } else {
                        int count = user.getFailedLoginCount() + 1;
                        user.setFailedLoginCount(count);
                        if (count >= 5) {
                            user.setStatus(AccountStatus.LOCKED);
                            user.setLockedUntil(now.plus(Duration.ofMinutes(15)));
                            auditService.record(AuditEventType.ACCOUNT_LOCKED, username, username, request, "Khóa tài khoản 15 phút do nhập sai mật khẩu 5 lần");
                        }
                    }
                    userRepository.save(user);
                    auditService.record(AuditEventType.LOGIN_FAILURE, username, username, request, "Đăng nhập thất bại: sai mật khẩu hoặc trạng thái không hợp lệ");
                }
            } else {
                // Timing attack mitigation: compute dummy BCrypt match so response time is indistinguishable
                dummyPasswordEncoder.matches(rawPassword != null ? rawPassword : "dummy", DUMMY_HASH);
                auditService.record(AuditEventType.LOGIN_FAILURE, username, username, request, "Đăng nhập thất bại: tài khoản không tồn tại");
            }
        }

        super.onAuthenticationFailure(request, response, exception);
    }
}
