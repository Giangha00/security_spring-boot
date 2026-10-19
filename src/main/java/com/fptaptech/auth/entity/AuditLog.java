package com.fptaptech.auth.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 50)
    private AuditEventType eventType;

    @Column(length = 100)
    private String username;

    @Column(length = 100)
    private String target;

    @Column(name = "ip_address", nullable = false, length = 64)
    private String ipAddress;

    @Column(name = "user_agent", nullable = false, length = 512)
    private String userAgent;

    @Column(length = 500)
    private String details;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected AuditLog() {}

    public AuditLog(AuditEventType eventType, String username, String target, String ipAddress, String userAgent, String details) {
        this.eventType = eventType;
        this.username = username;
        this.target = target;
        this.ipAddress = (ipAddress != null && !ipAddress.isBlank()) ? ipAddress : "127.0.0.1";
        this.userAgent = (userAgent != null && !userAgent.isBlank()) ? (userAgent.length() > 510 ? userAgent.substring(0, 510) : userAgent) : "Unknown";
        this.details = details;
    }

    @PrePersist
    void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = Instant.now();
        }
    }

    public Long getId() { return id; }
    public AuditEventType getEventType() { return eventType; }
    public String getUsername() { return username; }
    public String getTarget() { return target; }
    public String getIpAddress() { return ipAddress; }
    public String getUserAgent() { return userAgent; }
    public String getDetails() { return details; }
    public Instant getCreatedAt() { return createdAt; }
}
