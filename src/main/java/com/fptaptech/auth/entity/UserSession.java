package com.fptaptech.auth.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "user_sessions")
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "session_id", nullable = false, unique = true, length = 100)
    private String sessionId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUser user;

    @Column(nullable = false, length = 50)
    private String username;

    @Column(name = "ip_address", nullable = false, length = 64)
    private String ipAddress;

    @Column(name = "user_agent", nullable = false, length = 512)
    private String userAgent;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_accessed_at", nullable = false)
    private Instant lastAccessedAt;

    @Column(nullable = false)
    private boolean revoked = false;

    protected UserSession() {}

    public UserSession(String sessionId, AppUser user, String username, String ipAddress, String userAgent) {
        this.sessionId = sessionId;
        this.user = user;
        this.username = username;
        this.ipAddress = (ipAddress != null && !ipAddress.isBlank()) ? ipAddress : "127.0.0.1";
        this.userAgent = (userAgent != null && !userAgent.isBlank()) ? (userAgent.length() > 510 ? userAgent.substring(0, 510) : userAgent) : "Unknown";
    }

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        if (this.createdAt == null) {
            this.createdAt = now;
        }
        if (this.lastAccessedAt == null) {
            this.lastAccessedAt = now;
        }
    }

    public Long getId() { return id; }
    public String getSessionId() { return sessionId; }
    public AppUser getUser() { return user; }
    public String getUsername() { return username; }
    public String getIpAddress() { return ipAddress; }
    public String getUserAgent() { return userAgent; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastAccessedAt() { return lastAccessedAt; }
    public void setLastAccessedAt(Instant lastAccessedAt) { this.lastAccessedAt = lastAccessedAt; }
    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
}
