-- +goose Up
ALTER TABLE jobs ADD COLUMN context_ciphertext TEXT NULL;
-- +goose Down
ALTER TABLE jobs DROP COLUMN context_ciphertext;
