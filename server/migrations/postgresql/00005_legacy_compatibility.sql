-- +goose Up
CREATE TABLE legacy_id_map (
    source_table VARCHAR(64) NOT NULL,
    source_id VARCHAR(255) NOT NULL,
    target_id VARCHAR(32) NOT NULL,
    PRIMARY KEY (source_table, source_id)
);
CREATE INDEX legacy_target ON legacy_id_map (target_id);
CREATE TABLE legacy_api_credentials (
    user_id VARCHAR(32) PRIMARY KEY,
    legacy_uid VARCHAR(32) NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL,
    key_ciphertext TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE migration_archives (
    manifest_id VARCHAR(64) NOT NULL,
    source_table VARCHAR(64) NOT NULL,
    source_id VARCHAR(255) NOT NULL,
    data_ciphertext TEXT NOT NULL,
    PRIMARY KEY (manifest_id,source_table,source_id)
);
-- +goose Down
DROP TABLE migration_archives;
DROP TABLE legacy_api_credentials;
DROP TABLE legacy_id_map;
