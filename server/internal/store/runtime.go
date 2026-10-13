package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/dns-manager/dnsmgr/server/internal/database"
	"strings"
)

// Runtime updates preserve configuration, unknown fields and the
// scheduler's configuration revision. They are fenced by the active job lease.
func (s *Store) SaveObjectRuntime(ctx context.Context, o Object, j Job, fields map[string]any, eventKey string, event any) (Object, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return o, err
	}
	defer tx.Rollback()
	var enc string
	var config, version int64
	if err = tx.QueryRowContext(ctx, "SELECT data_ciphertext,config_version,version FROM objects WHERE id=? FOR UPDATE", o.ID).Scan(&enc, &config, &version); err != nil {
		return o, err
	}
	if config != o.ConfigVersion {
		return o, ErrConflict
	}
	var data map[string]any
	if err = s.Decrypt("object:"+o.ID, enc, &data); err != nil {
		return o, err
	}
	for key, value := range fields {
		data[key] = value
	}
	enc, err = s.Encrypt("object:"+o.ID, data)
	if err != nil {
		return o, err
	}
	result, err := tx.ExecContext(ctx, "UPDATE objects SET data_ciphertext=?,version=version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND version=? AND EXISTS(SELECT 1 FROM jobs WHERE id=? AND state='running' AND lease_owner=? AND fencing_token=? AND lease_until>UTC_TIMESTAMP(6))", enc, o.ID, version, j.ID, j.LeaseOwner, j.FencingToken)
	if err = leaseResult(result, err); err != nil {
		return o, err
	}
	if eventKey != "" {
		if err = s.insertBusinessEvent(ctx, tx, eventKey, event); err != nil {
			return o, err
		}
	}
	if err = tx.Commit(); err != nil {
		return o, err
	}
	return s.Object(ctx, o.ID)
}

func (s *Store) insertBusinessEvent(ctx context.Context, tx *database.Tx, key string, payload any) error {
	id, err := ID()
	if err != nil {
		return err
	}
	enc, err := s.Encrypt("business-event:"+id, payload)
	if err != nil {
		return err
	}
	query := "INSERT IGNORE INTO business_events(id,event_key,payload_ciphertext,created_at) VALUES(?,?,?,UTC_TIMESTAMP(6))"
	if s.Dialect() == database.MySQL {
		query = strings.Replace(query, "INSERT IGNORE", "INSERT", 1)
	}
	_, err = tx.ExecContext(ctx, query, id, key, enc)
	if IsDuplicate(err) {
		return nil
	}
	return err
}
func (s *Store) QueueBusinessEvent(ctx context.Context, key string, payload any) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.insertBusinessEvent(ctx, tx, key, payload); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) QueueBusinessEventTx(ctx context.Context, tx *database.Tx, key string, payload any) error {
	return s.insertBusinessEvent(ctx, tx, key, payload)
}

// DispatchOneEvent atomically fans out one durable event into encrypted channel
// messages and marks it dispatched. A crash rolls back both decisions.
func (s *Store) DispatchOneEvent(ctx context.Context, channels func(json.RawMessage) ([]string, error)) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id, key, enc string
	if err = tx.QueryRowContext(ctx, "SELECT id,event_key,payload_ciphertext FROM business_events WHERE dispatched_at IS NULL ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED").Scan(&id, &key, &enc); err != nil {
		return err
	}
	payload, err := s.Box.Open("business-event:"+id, enc)
	if err != nil {
		return err
	}
	ids, err := channels(payload)
	if err != nil {
		return err
	}
	for _, channel := range ids {
		if err = s.enqueueNotificationTx(ctx, tx, key+":"+channel, channel, json.RawMessage(payload)); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE business_events SET dispatched_at=UTC_TIMESTAMP(6) WHERE id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) enqueueNotificationTx(ctx context.Context, tx *database.Tx, key, channel string, payload any) error {
	id, err := ID()
	if err != nil {
		return err
	}
	enc, err := s.Encrypt("notification:"+id, payload)
	if err != nil {
		return err
	}
	query := "INSERT IGNORE INTO notification_outbox(id,event_key,channel_id,payload_ciphertext,state,attempts,next_run_at,created_at,updated_at) VALUES(?,?,?,?,'queued',0,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))"
	if s.Dialect() == database.MySQL {
		query = strings.Replace(query, "INSERT IGNORE", "INSERT", 1)
	}
	_, err = tx.ExecContext(ctx, query, id, key, channel, enc)
	if IsDuplicate(err) {
		return nil
	}
	return err
}

func (s *Store) EnqueueNotificationTx(ctx context.Context, tx *database.Tx, key, channel string, payload any) error {
	return s.enqueueNotificationTx(ctx, tx, key, channel, payload)
}

func (s *Store) FinishNotification(ctx context.Context, o OutboxMessage, state string, delaySeconds int) error {
	if state != "sent" && state != "retry" && state != "failed" {
		return errors.New("invalid notification state")
	}
	r, err := s.DB.ExecContext(ctx, "UPDATE notification_outbox SET state=?,next_run_at=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL ? SECOND),updated_at=UTC_TIMESTAMP(6) WHERE id=? AND state='sending' AND fencing_token=?", state, delaySeconds, o.ID, o.FencingToken)
	return leaseResult(r, err)
}
