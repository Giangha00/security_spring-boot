package com.fptaptech.auth.config;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.AuditEventType;
import com.fptaptech.auth.entity.Role;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.AuditService;
import com.fptaptech.auth.service.SessionManagementService;
import com.fptaptech.auth.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final SessionManagementService sessionManagementService;
    private final AuditService auditService;

    public CustomAuthenticationSuccessHandler(UserRepository userRepository,
                                              SessionManagementService sessionManagementService,
                                              AuditService auditService) {
        this.userRepository = userRepository;
        this.sessionManagementService = sessionManagementService;
        this.auditService = auditService;
        setDefaultTargetUrl("/");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String username = authentication.getName();
        AppUser user = userRepository.findByUsername(UserService.normalize(username)).orElse(null);

        if (user != null) {
            user.setFailedLoginCount(0);
            user.setFirstFailedLoginAt(null);
            user.setLockedUntil(null);
            userRepository.save(user);

            sessionManagementService.registerLoginSession(user, request);
            auditService.record(AuditEventType.LOGIN_SUCCESS, username, username, request, "Đăng nhập thành công");

            // F6: LECTURER and ADMIN must set up 2FA before entering system
            if ((user.hasRole(Role.LECTURER) || user.hasRole(Role.ADMIN)) && !user.isTotpEnabled()) {
                getRedirectStrategy().sendRedirect(request, response, "/2fa/setup");
                return;
            }
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
