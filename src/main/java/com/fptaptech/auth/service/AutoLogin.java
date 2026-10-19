package com.fptaptech.auth.service;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

@Component
public class AutoLogin {

    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final SessionManagementService sessionManagementService;
    private final SecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();
    private final SecurityContextHolderStrategy holder = SecurityContextHolder.getContextHolderStrategy();

    public AutoLogin(UserDetailsService userDetailsService,
                     UserRepository userRepository,
                     SessionManagementService sessionManagementService) {
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
        this.sessionManagementService = sessionManagementService;
    }

    public void login(String username, HttpServletRequest request, HttpServletResponse response) {
        UserDetails user = userDetailsService.loadUserByUsername(username);
        var authentication = UsernamePasswordAuthenticationToken.authenticated(
                user, null, user.getAuthorities());

        if (request.getSession(false) != null) {
            request.changeSessionId();
        }

        SecurityContext context = holder.createEmptyContext();
        context.setAuthentication(authentication);
        holder.setContext(context);
        contextRepository.saveContext(context, request, response);

        userRepository.findByUsername(UserService.normalize(username)).ifPresent(appUser -> {
            sessionManagementService.registerLoginSession(appUser, request);
        });
    }
}
