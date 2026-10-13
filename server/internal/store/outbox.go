package store

import (
	"context"
	"encoding/json"
)

type OutboxMessage struct {
	ID           string
	ChannelID    string
	Payload      json.RawMessage
	Attempts     int
	FencingToken int64
}

func (s *Store) EnqueueNotification(ctx context.Context, eventKey, channelID string, payload any) error {
	id, err := ID()
	if err != nil {
		return err
	}
	enc, err := s.Encrypt("notification:"+id, payload)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, "INSERT INTO notification_outbox(id,event_key,channel_id,payload_ciphertext,state,attempts,next_run_at,created_at,updated_at) VALUES (?,?,?,?,'queued',0,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))", id, eventKey, channelID, enc)
	if IsDuplicate(err) {
		return nil
	}
	return err
}
func (s *Store) ClaimNotification(ctx context.Context) (OutboxMessage, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return OutboxMessage{}, err
	}
	defer tx.Rollback()
	var o OutboxMessage
	var enc string
	err = tx.QueryRowContext(ctx, "SELECT id,channel_id,payload_ciphertext,attempts,fencing_token FROM notification_outbox WHERE state IN ('queued','retry','sending') AND next_run_at<=UTC_TIMESTAMP(6) ORDER BY next_run_at LIMIT 1 FOR UPDATE SKIP LOCKED").Scan(&o.ID, &o.ChannelID, &enc, &o.Attempts, &o.FencingToken)
	if err != nil {
		return o, err
	}
	o.Payload, err = s.Box.Open("notification:"+o.ID, enc)
	if err != nil {
		return o, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE notification_outbox SET state='sending',attempts=attempts+1,fencing_token=fencing_token+1,next_run_at=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 60 SECOND),updated_at=UTC_TIMESTAMP(6) WHERE id=?", o.ID)
	if err != nil {
		return o, err
	}
	o.FencingToken++
	o.Attempts++
	return o, tx.Commit()
}
