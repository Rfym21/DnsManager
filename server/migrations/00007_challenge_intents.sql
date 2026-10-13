-- +goose Up
CREATE TABLE dns_challenge_intents (
    job_id VARCHAR(32) NOT NULL,
    challenge_key VARCHAR(64) NOT NULL,
    domain_id VARCHAR(32) NOT NULL,
    intent_ciphertext LONGTEXT NOT NULL,
    state VARCHAR(32) NOT NULL,
    record_id VARCHAR(255) NOT NULL DEFAULT '',
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY(job_id,challenge_key),
    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);
-- +goose Down
DROP TABLE dns_challenge_intents;
