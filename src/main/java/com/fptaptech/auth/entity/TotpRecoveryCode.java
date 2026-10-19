package com.fptaptech.auth.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "totp_recovery_codes")
public class TotpRecoveryCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUser user;

    @Column(name = "code_hash", nullable = false, length = 64)
    private String codeHash;

    @Column(nullable = false)
    private boolean used = false;

    @Column(name = "used_at")
    private Instant usedAt;

    protected TotpRecoveryCode() {}

    public TotpRecoveryCode(AppUser user, String codeHash) {
        this.user = user;
        this.codeHash = codeHash;
        this.used = false;
    }

    public Long getId() { return id; }
    public AppUser getUser() { return user; }
    public String getCodeHash() { return codeHash; }
    public boolean isUsed() { return used; }
    public void setUsed(boolean used) { this.used = used; }
    public Instant getUsedAt() { return usedAt; }
    public void setUsedAt(Instant usedAt) { this.usedAt = usedAt; }
}
