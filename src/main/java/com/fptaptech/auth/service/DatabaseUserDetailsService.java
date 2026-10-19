package com.fptaptech.auth.service;

import com.fptaptech.auth.entity.AccountStatus;
import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class DatabaseUserDetailsService implements UserDetailsService, UserDetailsPasswordService {

    private final UserRepository users;

    public DatabaseUserDetailsService(UserRepository users) {
        this.users = users;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {
        String normalized = UserService.normalize(username);
        AppUser user = users.findByUsername(normalized)
                .or(() -> users.findByEmail(UserService.normalizeEmail(username)))
                .orElseThrow(() -> new UsernameNotFoundException("Không tìm thấy tài khoản"));

        boolean isLocked = user.getStatus() == AccountStatus.LOCKED
                && user.getLockedUntil() != null
                && user.getLockedUntil().isAfter(Instant.now());

        boolean isEnabled = user.isEnabled() && user.getStatus() == AccountStatus.ACTIVE;

        return User.withUsername(user.getUsername())
                .password(user.getPasswordHash())
                .disabled(!isEnabled)
                .accountLocked(isLocked)
                .authorities(user.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority(role.getName()))
                        .toList())
                .build();
    }

    @Override
    @Transactional
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        AppUser appUser = users.findByUsername(UserService.normalize(user.getUsername()))
                .orElseThrow(() -> new UsernameNotFoundException("Không tìm thấy tài khoản để nâng cấp mật khẩu"));
        appUser.setPasswordHash(newPassword);
        users.save(appUser);
        return User.withUserDetails(user).password(newPassword).build();
    }
}
