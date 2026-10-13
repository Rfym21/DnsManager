-- +goose Up
ALTER TABLE jobs ADD COLUMN context_ciphertext LONGTEXT NULL;
-- +goose Down
ALTER TABLE jobs DROP COLUMN context_ciphertext;
