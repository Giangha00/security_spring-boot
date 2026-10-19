package com.fptaptech.auth.service;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.UserSession;
import com.fptaptech.auth.repository.UserSessionRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class SessionManagementService {

    private final UserSessionRepository userSessionRepository;
    private final JdbcTemplate jdbcTemplate;

    public SessionManagementService(UserSessionRepository userSessionRepository, JdbcTemplate jdbcTemplate) {
        this.userSessionRepository = userSessionRepository;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    public UserSession registerLoginSession(AppUser user, HttpServletRequest request) {
        String sessionId = null;
        if (request != null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                sessionId = session.getId();
            } else {
                HttpSession newSession = request.getSession(true);
                if (newSession != null) {
                    sessionId = newSession.getId();
                }
            }
        }
        if (sessionId == null || sessionId.isBlank()) {
            sessionId = UUID.randomUUID().toString();
        }

        String ip = "127.0.0.1";
        String ua = "Unknown";
        if (request != null) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                ip = forwarded.split(",")[0].trim();
            } else if (request.getRemoteAddr() != null) {
                ip = request.getRemoteAddr();
            }
            String uaHeader = request.getHeader("User-Agent");
            if (uaHeader != null && !uaHeader.isBlank()) {
                ua = uaHeader;
            }
        }

        // Limit concurrent sessions to max 2 active sessions per user
        List<UserSession> activeSessions = userSessionRepository
                .findByUsernameAndRevokedFalseOrderByCreatedAtAsc(user.getUsername());
        
        while (activeSessions.size() >= 2) {
            UserSession oldest = activeSessions.remove(0);
            oldest.setRevoked(true);
            userSessionRepository.save(oldest);
        }

        Optional<UserSession> existing = userSessionRepository.findBySessionId(sessionId);
        if (existing.isPresent()) {
            UserSession session = existing.get();
            session.setRevoked(false);
            session.setLastAccessedAt(Instant.now());
            return userSessionRepository.save(session);
        }

        UserSession newSession = new UserSession(sessionId, user, user.getUsername(), ip, ua);
        return userSessionRepository.save(newSession);
    }

    @Transactional(readOnly = true)
    public boolean isSessionRevoked(String sessionId) {
        if (sessionId == null) return false;
        return userSessionRepository.findBySessionId(sessionId)
                .map(UserSession::isRevoked)
                .orElse(false);
    }

    @Transactional(readOnly = true)
    public List<UserSession> getActiveSessions(String username) {
        return userSessionRepository.findByUsernameAndRevokedFalseOrderByCreatedAtDesc(username);
    }

    @Transactional
    public void updateLastAccessed(String sessionId) {
        userSessionRepository.findBySessionId(sessionId).ifPresent(s -> {
            s.setLastAccessedAt(Instant.now());
            userSessionRepository.save(s);
        });
    }

    @Transactional
    public void revokeSession(String sessionId, String username) {
        userSessionRepository.findBySessionId(sessionId).ifPresent(s -> {
            if (username == null || username.equalsIgnoreCase(s.getUsername())) {
                s.setRevoked(true);
                userSessionRepository.save(s);
            }
        });
    }

    @Transactional
    public void revokeSessionById(Long id, String username) {
        userSessionRepository.findById(id).ifPresent(s -> {
            if (username == null || username.equalsIgnoreCase(s.getUsername())) {
                s.setRevoked(true);
                userSessionRepository.save(s);
            }
        });
    }

    @Transactional
    public void revokeAllUserSessionsExcept(String username, String keepSessionId) {
        List<UserSession> activeSessions = userSessionRepository
                .findByUsernameAndRevokedFalseOrderByCreatedAtAsc(username);
        for (UserSession s : activeSessions) {
            if (keepSessionId == null || !keepSessionId.equals(s.getSessionId())) {
                s.setRevoked(true);
                userSessionRepository.save(s);
            }
        }
        revokeRememberMeTokens(username);
    }

    @Transactional
    public void revokeAllUserSessions(String username) {
        List<UserSession> activeSessions = userSessionRepository
                .findByUsernameAndRevokedFalseOrderByCreatedAtAsc(username);
        for (UserSession s : activeSessions) {
            s.setRevoked(true);
            userSessionRepository.save(s);
        }
        revokeRememberMeTokens(username);
    }

    private void revokeRememberMeTokens(String username) {
        try {
            jdbcTemplate.update("DELETE FROM persistent_logins WHERE LOWER(username) = LOWER(?)", username);
        } catch (Exception ignored) {
        }
    }
}
