package automation

import (
	"context"
	"database/sql"
	"time"
)

// Bounded deletes preserve active/unknown jobs and unpublished event evidence.
func (r *Runner) cleanup(ctx context.Context) error {
	var policy struct {
		AuditDays int `json:"audit_days"`
		JobDays   int `json:"job_days"`
	}
	if err := r.Store.Setting(ctx, "retention", &policy); err != nil && err != sql.ErrNoRows {
		return err
	}
	if policy.AuditDays < 7 {
		policy.AuditDays = 180
	}
	if policy.JobDays < 7 {
		policy.JobDays = 90
	}
	release, err := r.Store.LockResources(ctx, []string{"retention"})
	if err != nil {
		return nil
	}
	defer release()
	audit := time.Now().UTC().AddDate(0, 0, -policy.AuditDays)
	jobs := time.Now().UTC().AddDate(0, 0, -policy.JobDays)
	for _, item := range []struct {
		query string
		args  []any
	}{
		{"DELETE FROM sessions WHERE expires_at<UTC_TIMESTAMP(6) LIMIT 500", nil},
		{"DELETE FROM login_attempts WHERE expires_at<UTC_TIMESTAMP(6) LIMIT 500", nil},
		{"DELETE FROM login_tickets WHERE expires_at<UTC_TIMESTAMP(6) LIMIT 500", nil},
		{"DELETE FROM settings WHERE name LIKE 'captcha_used:%' AND updated_at<DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 DAY) LIMIT 500", nil},
		{"DELETE FROM worker_heartbeats WHERE last_seen<DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 DAY) LIMIT 500", nil},
		{"DELETE FROM audit_events WHERE created_at<? LIMIT 500", []any{audit}},
		{"DELETE FROM jobs WHERE state IN ('succeeded','failed','cancelled','partial') AND updated_at<? AND NOT EXISTS(SELECT 1 FROM business_events b WHERE b.event_key LIKE CONCAT('%',jobs.id,'%') AND b.dispatched_at IS NULL) LIMIT 100", []any{jobs}},
		{"DELETE FROM notification_outbox WHERE state='sent' AND updated_at<? LIMIT 500", []any{jobs}},
		{"DELETE FROM business_events WHERE dispatched_at IS NOT NULL AND created_at<? LIMIT 500", []any{jobs}},
	} {
		if _, err = r.Store.DB.ExecContext(ctx, item.query, item.args...); err != nil {
			return err
		}
	}
	return nil
}
