-- +goose Up
CREATE TABLE legacy_identities (
    source_id VARCHAR(128) NOT NULL,
    legacy_id VARCHAR(32) NOT NULL,
    user_id VARCHAR(32) NOT NULL,
    api_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    api_key_ciphertext TEXT NULL,
    PRIMARY KEY(source_id,legacy_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE legacy_resources (
    source_id VARCHAR(128) NOT NULL,
    source_table VARCHAR(64) NOT NULL,
    source_id_value VARCHAR(255) NOT NULL,
    target_id VARCHAR(32) NOT NULL,
    PRIMARY KEY(source_id,source_table,source_id_value)
);
CREATE TABLE migration_manifests (
    id VARCHAR(64) PRIMARY KEY,
    source_id VARCHAR(128) NOT NULL,
    archive_ciphertext LONGTEXT NOT NULL,
    report JSON NOT NULL,
    created_at DATETIME(6) NOT NULL
);
-- +goose Down
DROP TABLE migration_manifests;
DROP TABLE legacy_resources;
DROP TABLE legacy_identities;
