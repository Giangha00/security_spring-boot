package com.fptaptech.auth.config;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.Role;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class TwoFactorEnforcementFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;

    public TwoFactorEnforcementFilter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();

        if (path.startsWith("/2fa") || path.startsWith("/logout") || path.startsWith("/login") || path.startsWith("/css") || path.startsWith("/js") || path.startsWith("/images") || path.equals("/error")) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
            AppUser user = userRepository.findByUsername(UserService.normalize(auth.getName())).orElse(null);
            if (user != null && (user.hasRole(Role.LECTURER) || user.hasRole(Role.ADMIN)) && !user.isTotpEnabled()) {
                response.sendRedirect(request.getContextPath() + "/2fa/setup");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
