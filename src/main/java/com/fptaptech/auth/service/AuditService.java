package com.fptaptech.auth.service;

import com.fptaptech.auth.entity.AuditEventType;
import com.fptaptech.auth.entity.AuditLog;
import com.fptaptech.auth.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Transactional
    public void record(AuditEventType type, String username, String target, HttpServletRequest request, String details) {
        String ip = "127.0.0.1";
        String ua = "Unknown";
        if (request != null) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                ip = forwarded.split(",")[0].trim();
            } else if (request.getRemoteAddr() != null) {
                ip = request.getRemoteAddr();
            }
            String userAgentHeader = request.getHeader("User-Agent");
            if (userAgentHeader != null && !userAgentHeader.isBlank()) {
                ua = userAgentHeader;
            }
        }
        record(type, username, target, ip, ua, details);
    }

    @Transactional
    public void record(AuditEventType type, String username, String target, String ipAddress, String userAgent, String details) {
        AuditLog log = new AuditLog(type, username, target, ipAddress, userAgent, details);
        auditLogRepository.save(log);
    }
}
