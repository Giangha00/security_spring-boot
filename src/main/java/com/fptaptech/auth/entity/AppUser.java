package com.fptaptech.auth.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(name = "password_hash", nullable = false, length = 100)
    private String passwordHash;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(length = 120, unique = true)
    private String email;

    @Column(name = "full_name", length = 100)
    private String fullName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AccountStatus status = AccountStatus.ACTIVE;

    @Column(name = "failed_login_count", nullable = false)
    private int failedLoginCount = 0;

    @Column(name = "first_failed_login_at")
    private Instant firstFailedLoginAt;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "totp_secret_enc", length = 512)
    private String totpSecretEnc;

    @Column(name = "totp_enabled", nullable = false)
    private boolean totpEnabled = false;

    @Column(name = "verification_resend_count", nullable = false)
    private int verificationResendCount = 0;

    @Column(name = "verification_resend_window_start")
    private Instant verificationResendWindowStart;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    protected AppUser() {}

    public AppUser(String username, String passwordHash) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.status = AccountStatus.ACTIVE;
        this.enabled = true;
    }

    public AppUser(String username, String email, String passwordHash, AccountStatus status) {
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.status = status;
        this.enabled = (status == AccountStatus.ACTIVE);
    }

    @PrePersist
    void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = Instant.now();
        }
    }

    public boolean hasRole(String roleName) {
        if (roles == null) return false;
        return roles.stream().anyMatch(r -> roleName.equals(r.getName()));
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public Instant getCreatedAt() { return createdAt; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getFullName() { return fullName; }
    public void setFullName(String fullName) { this.fullName = fullName; }
    public AccountStatus getStatus() { return status; }
    public void setStatus(AccountStatus status) {
        this.status = status;
        this.enabled = (status == AccountStatus.ACTIVE);
    }
    public int getFailedLoginCount() { return failedLoginCount; }
    public void setFailedLoginCount(int failedLoginCount) { this.failedLoginCount = failedLoginCount; }
    public Instant getFirstFailedLoginAt() { return firstFailedLoginAt; }
    public void setFirstFailedLoginAt(Instant firstFailedLoginAt) { this.firstFailedLoginAt = firstFailedLoginAt; }
    public Instant getLockedUntil() { return lockedUntil; }
    public void setLockedUntil(Instant lockedUntil) { this.lockedUntil = lockedUntil; }
    public String getTotpSecretEnc() { return totpSecretEnc; }
    public void setTotpSecretEnc(String totpSecretEnc) { this.totpSecretEnc = totpSecretEnc; }
    public boolean isTotpEnabled() { return totpEnabled; }
    public void setTotpEnabled(boolean totpEnabled) { this.totpEnabled = totpEnabled; }
    public int getVerificationResendCount() { return verificationResendCount; }
    public void setVerificationResendCount(int verificationResendCount) { this.verificationResendCount = verificationResendCount; }
    public Instant getVerificationResendWindowStart() { return verificationResendWindowStart; }
    public void setVerificationResendWindowStart(Instant verificationResendWindowStart) { this.verificationResendWindowStart = verificationResendWindowStart; }
    public Set<Role> getRoles() { return roles; }
    public void setRoles(Set<Role> roles) { this.roles = roles; }
}
