package com.fptaptech.auth.config;

import com.fptaptech.auth.service.SessionManagementService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SessionTrackingFilter extends OncePerRequestFilter {

    private final SessionManagementService sessionManagementService;

    public SessionTrackingFilter(SessionManagementService sessionManagementService) {
        this.sessionManagementService = sessionManagementService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            String sessionId = session.getId();
            if (sessionManagementService.isSessionRevoked(sessionId)) {
                session.invalidate();
                SecurityContextHolder.clearContext();
                response.sendRedirect(request.getContextPath() + "/login?expired");
                return;
            }

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
                sessionManagementService.updateLastAccessed(sessionId);
            }
        }

        filterChain.doFilter(request, response);
    }
}
