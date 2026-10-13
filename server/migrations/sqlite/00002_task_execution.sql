-- +goose Up
ALTER TABLE jobs ADD COLUMN checkpoint_ciphertext TEXT NULL;
ALTER TABLE jobs ADD COLUMN result_ciphertext TEXT NULL;
ALTER TABLE jobs ADD COLUMN domain_id VARCHAR(32) NULL;
ALTER TABLE jobs ADD COLUMN occurrence_key VARCHAR(255) NULL;
CREATE UNIQUE INDEX jobs_occurrence_key ON jobs (occurrence_key);
CREATE TABLE job_items (
    job_id VARCHAR(32) NOT NULL,
    item_index INT NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'pending',
    detail_ciphertext TEXT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (job_id, item_index),
    FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
);
CREATE TABLE worker_heartbeats (
    worker_id VARCHAR(64) NOT NULL PRIMARY KEY,
    last_seen DATETIME NOT NULL,
    capabilities JSON NOT NULL CHECK (json_valid(capabilities))
);
CREATE TABLE notification_outbox (
    id VARCHAR(32) NOT NULL PRIMARY KEY,
    event_key VARCHAR(255) NOT NULL UNIQUE,
    channel_id VARCHAR(32) NOT NULL,
    payload_ciphertext TEXT NOT NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'queued',
    attempts INT NOT NULL DEFAULT 0,
    next_run_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
CREATE INDEX outbox_queue ON notification_outbox (state,next_run_at);
CREATE TABLE login_tickets (
    token_hash VARCHAR(64) NOT NULL PRIMARY KEY,
    domain_id VARCHAR(32) NOT NULL,
    issuer_id VARCHAR(32) NOT NULL,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME NULL
);
CREATE TABLE object_schedule_state (
    object_id VARCHAR(32) NOT NULL PRIMARY KEY,
    next_run_at DATETIME NULL,
    last_run_at DATETIME NULL,
    revision BIGINT NOT NULL,
    FOREIGN KEY (object_id) REFERENCES objects(id) ON DELETE CASCADE
);
CREATE INDEX object_schedule_due ON object_schedule_state (next_run_at);
ALTER TABLE domains ADD COLUMN registered_at DATETIME NULL;
ALTER TABLE domains ADD COLUMN expires_at DATETIME NULL;
ALTER TABLE domains ADD COLUMN expiry_checked_at DATETIME NULL;
ALTER TABLE domains ADD COLUMN expiry_notice_at DATETIME NULL;
ALTER TABLE domains ADD COLUMN expiry_notice_enabled BOOLEAN NOT NULL DEFAULT FALSE;
-- +goose Down
ALTER TABLE domains DROP COLUMN registered_at;
ALTER TABLE domains DROP COLUMN expires_at;
ALTER TABLE domains DROP COLUMN expiry_checked_at;
ALTER TABLE domains DROP COLUMN expiry_notice_at;
ALTER TABLE domains DROP COLUMN expiry_notice_enabled;
DROP TABLE object_schedule_state;
DROP TABLE login_tickets;
DROP TABLE notification_outbox;
DROP TABLE worker_heartbeats;
DROP TABLE job_items;
DROP INDEX jobs_occurrence_key;
ALTER TABLE jobs DROP COLUMN checkpoint_ciphertext;
ALTER TABLE jobs DROP COLUMN result_ciphertext;
ALTER TABLE jobs DROP COLUMN domain_id;
ALTER TABLE jobs DROP COLUMN occurrence_key;
