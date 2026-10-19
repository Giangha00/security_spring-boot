INSERT INTO roles (name) VALUES ('ROLE_STUDENT'), ('ROLE_LECTURER');

ALTER TABLE users ADD COLUMN email VARCHAR(120) UNIQUE;
ALTER TABLE users ADD COLUMN full_name VARCHAR(100);
ALTER TABLE users ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE users ADD COLUMN failed_login_count INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN first_failed_login_at DATETIME(6) NULL;
ALTER TABLE users ADD COLUMN locked_until DATETIME(6) NULL;
ALTER TABLE users ADD COLUMN totp_secret_enc VARCHAR(512) NULL;
ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN verification_resend_count INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN verification_resend_window_start DATETIME(6) NULL;

CREATE TABLE security_tokens (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT       NOT NULL,
    token_hash VARCHAR(64)  NOT NULL UNIQUE,
    token_type VARCHAR(30)  NOT NULL,
    expires_at DATETIME(6)  NOT NULL,
    used_at    DATETIME(6)  NULL,
    created_at DATETIME(6)  NOT NULL,
    CONSTRAINT fk_security_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE password_history (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id       BIGINT       NOT NULL,
    password_hash VARCHAR(100) NOT NULL,
    created_at    DATETIME(6)  NOT NULL,
    CONSTRAINT fk_password_history_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE totp_recovery_codes (
    id        BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id   BIGINT      NOT NULL,
    code_hash VARCHAR(64) NOT NULL,
    used      BOOLEAN     NOT NULL DEFAULT FALSE,
    used_at   DATETIME(6) NULL,
    CONSTRAINT fk_totp_recovery_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE persistent_logins (
    username  VARCHAR(64) NOT NULL,
    series    VARCHAR(64) PRIMARY KEY,
    token     VARCHAR(64) NOT NULL,
    last_used TIMESTAMP   NOT NULL
);

CREATE TABLE user_sessions (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    session_id       VARCHAR(100) NOT NULL UNIQUE,
    user_id          BIGINT       NOT NULL,
    username         VARCHAR(50)  NOT NULL,
    ip_address       VARCHAR(64)  NOT NULL,
    user_agent       VARCHAR(512) NOT NULL,
    created_at       DATETIME(6)  NOT NULL,
    last_accessed_at DATETIME(6)  NOT NULL,
    revoked          BOOLEAN      NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE audit_logs (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50)  NOT NULL,
    username   VARCHAR(100) NULL,
    target     VARCHAR(100) NULL,
    ip_address VARCHAR(64)  NOT NULL,
    user_agent VARCHAR(512) NOT NULL,
    details    VARCHAR(500) NULL,
    created_at DATETIME(6)  NOT NULL
);
