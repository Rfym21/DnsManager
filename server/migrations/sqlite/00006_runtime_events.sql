-- +goose Up
ALTER TABLE objects ADD COLUMN config_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE notification_outbox ADD COLUMN fencing_token BIGINT NOT NULL DEFAULT 0;
CREATE TABLE business_events (
    id VARCHAR(32) NOT NULL PRIMARY KEY,
    event_key VARCHAR(255) NOT NULL UNIQUE,
    payload_ciphertext TEXT NOT NULL,
    dispatched_at DATETIME NULL,
    created_at DATETIME NOT NULL
);
CREATE INDEX pending_events ON business_events (dispatched_at,created_at);
-- +goose Down
DROP TABLE business_events;
ALTER TABLE notification_outbox DROP COLUMN fencing_token;
ALTER TABLE objects DROP COLUMN config_version;
