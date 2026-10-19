package com.fptaptech.auth.config;

import com.fptaptech.auth.entity.AuditEventType;
import com.fptaptech.auth.service.AuditService;
import com.fptaptech.auth.service.SessionManagementService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private final SessionManagementService sessionManagementService;
    private final AuditService auditService;

    public CustomLogoutSuccessHandler(SessionManagementService sessionManagementService, AuditService auditService) {
        this.sessionManagementService = sessionManagementService;
        this.auditService = auditService;
        setDefaultTargetUrl("/login?logout");
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (authentication != null) {
            String username = authentication.getName();
            HttpSession session = request.getSession(false);
            if (session != null) {
                sessionManagementService.revokeSession(session.getId(), username);
            }
            auditService.record(AuditEventType.LOGOUT, username, username, request, "Đăng xuất tài khoản");
        }
        super.onLogoutSuccess(request, response, authentication);
    }
}
