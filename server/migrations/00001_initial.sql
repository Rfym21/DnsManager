-- +goose Up
CREATE TABLE users (
    id VARCHAR(32) PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    totp_secret TEXT NULL,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    preferences JSON NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL
);
CREATE TABLE domain_grants (
    user_id VARCHAR(32) NOT NULL,
    domain_id VARCHAR(32) NOT NULL,
    permissions JSON NOT NULL,
    PRIMARY KEY (user_id, domain_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE sessions (
    token_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(32) NOT NULL,
    domain_id VARCHAR(32) NULL,
    csrf_token VARCHAR(64) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX sessions_expiry (expires_at)
);
CREATE TABLE api_tokens (
    id VARCHAR(32) PRIMARY KEY,
    user_id VARCHAR(32) NOT NULL,
    name VARCHAR(128) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    scopes JSON NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    last_used_at DATETIME(6) NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE provider_accounts (
    id VARCHAR(32) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    config_ciphertext MEDIUMTEXT NOT NULL,
    remark VARCHAR(1024) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'unverified',
    last_error VARCHAR(1024) NOT NULL DEFAULT '',
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL
);
CREATE TABLE domains (
    id VARCHAR(32) PRIMARY KEY,
    account_id VARCHAR(32) NOT NULL,
    provider_domain_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    ascii_name VARCHAR(255) NOT NULL,
    category VARCHAR(128) NOT NULL DEFAULT '',
    remark VARCHAR(1024) NOT NULL DEFAULT '',
    quicklogin_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    hidden BOOLEAN NOT NULL DEFAULT FALSE,
    fetched_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    UNIQUE KEY domain_account_name (account_id, ascii_name),
    FOREIGN KEY (account_id) REFERENCES provider_accounts(id)
);
CREATE TABLE objects (
    id VARCHAR(32) PRIMARY KEY,
    kind VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    domain_id VARCHAR(32) NULL,
    owner_id VARCHAR(32) NOT NULL,
    data_ciphertext LONGTEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    INDEX objects_kind (kind, updated_at)
);
CREATE TABLE jobs (
    id VARCHAR(32) PRIMARY KEY,
    kind VARCHAR(64) NOT NULL,
    resource_id VARCHAR(32) NOT NULL,
    owner_id VARCHAR(32) NOT NULL,
    payload_ciphertext LONGTEXT NOT NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'queued',
    attempt INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    lease_owner VARCHAR(64) NULL,
    lease_until DATETIME(6) NULL,
    fencing_token BIGINT NOT NULL DEFAULT 0,
    next_run_at DATETIME(6) NOT NULL,
    idempotency_key VARCHAR(255) NULL UNIQUE,
    completed INT NOT NULL DEFAULT 0,
    total INT NOT NULL DEFAULT 0,
    error_code VARCHAR(64) NOT NULL DEFAULT '',
    error_message VARCHAR(1024) NOT NULL DEFAULT '',
    cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    INDEX jobs_queue (state, next_run_at, lease_until),
    INDEX jobs_owner (owner_id, created_at)
);
CREATE TABLE job_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    job_id VARCHAR(32) NOT NULL,
    level VARCHAR(16) NOT NULL,
    message VARCHAR(2048) NOT NULL,
    data JSON NULL,
    created_at DATETIME(6) NOT NULL,
    FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
    INDEX job_events_job (job_id, id)
);
CREATE TABLE audit_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    actor_id VARCHAR(32) NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    domain_id VARCHAR(32) NULL,
    request_id VARCHAR(64) NOT NULL,
    detail JSON NOT NULL,
    created_at DATETIME(6) NOT NULL,
    INDEX audit_domain (domain_id, id),
    INDEX audit_actor (actor_id, id)
);
CREATE TABLE settings (
    name VARCHAR(128) PRIMARY KEY,
    ciphertext LONGTEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    updated_at DATETIME(6) NOT NULL
);
CREATE TABLE login_attempts (
    attempt_key VARCHAR(64) PRIMARY KEY,
    failures INT NOT NULL,
    expires_at DATETIME(6) NOT NULL
);
CREATE TABLE owner_registry (
    scope VARCHAR(255) PRIMARY KEY,
    owner VARCHAR(16) NOT NULL,
    epoch BIGINT NOT NULL DEFAULT 1,
    cutover_at DATETIME(6) NOT NULL
);
CREATE TABLE migration_imports (
    manifest_id VARCHAR(64) NOT NULL,
    source_table VARCHAR(64) NOT NULL,
    source_id VARCHAR(255) NOT NULL,
    target_id VARCHAR(32) NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    imported_at DATETIME(6) NOT NULL,
    PRIMARY KEY (manifest_id, source_table, source_id)
);

-- +goose Down
DROP TABLE migration_imports;
DROP TABLE owner_registry;
DROP TABLE login_attempts;
DROP TABLE settings;
DROP TABLE audit_events;
DROP TABLE job_events;
DROP TABLE jobs;
DROP TABLE objects;
DROP TABLE domains;
DROP TABLE provider_accounts;
DROP TABLE api_tokens;
DROP TABLE sessions;
DROP TABLE domain_grants;
DROP TABLE users;
