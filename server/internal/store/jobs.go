package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dns-manager/dnsmgr/server/internal/notifications"
	"time"
)

var ErrLeaseLost = errors.New("job lease lost")
var ErrCancelled = errors.New("job cancellation requested")
var ErrResultUnknown = errors.New("resource has unresolved remote write")

type Job struct {
	ID              string          `json:"id"`
	Kind            string          `json:"kind"`
	ResourceID      string          `json:"resource_id"`
	OwnerID         string          `json:"owner_id"`
	DomainID        string          `json:"domain_id,omitempty"`
	State           string          `json:"state"`
	Attempt         int             `json:"attempt"`
	MaxAttempts     int             `json:"max_attempts"`
	LeaseOwner      string          `json:"-"`
	FencingToken    int64           `json:"-"`
	NextRunAt       time.Time       `json:"next_run_at"`
	Completed       int             `json:"completed"`
	Total           int             `json:"total"`
	ErrorCode       string          `json:"error_code,omitempty"`
	ErrorMessage    string          `json:"error_message,omitempty"`
	CancelRequested bool            `json:"cancel_requested"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	Payload         json.RawMessage `json:"-"`
	Checkpoint      json.RawMessage `json:"-"`
	Result          json.RawMessage `json:"result,omitempty"`
	IdempotencyKey  string          `json:"-"`
	OccurrenceKey   string          `json:"-"`
	Submission      *JobSubmission  `json:"-"`
}

// The worker retains the authority of the submitter rather than elevating a
// domain session or a scoped token to the owner's full user permissions.
type JobSubmission struct {
	DomainID  string   `json:"domain_id,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	Token     bool     `json:"token"`
	TokenHash string   `json:"token_hash,omitempty"`
}

func Submission(p Principal) *JobSubmission {
	return &JobSubmission{DomainID: p.DomainID, Scopes: p.Scopes, Token: p.Token, TokenHash: p.TokenHash}
}

type JobEvent struct {
	ID        string          `json:"id"`
	JobID     string          `json:"job_id"`
	Level     string          `json:"level"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}
type JobItem struct {
	Index      int             `json:"index"`
	ResourceID string          `json:"resource_id"`
	State      string          `json:"state"`
	Detail     json.RawMessage `json:"detail,omitempty"`
}

const jobColumns = "id,kind,resource_id,owner_id,domain_id,state,attempt,max_attempts,lease_owner,fencing_token,next_run_at,completed,total,error_code,error_message,cancel_requested,created_at,updated_at,payload_ciphertext,checkpoint_ciphertext,result_ciphertext,context_ciphertext"

func (s *Store) scanJob(row interface{ Scan(...any) error }) (Job, error) {
	var j Job
	var domain, lease, checkpoint, result, submission sql.NullString
	var payload string
	err := row.Scan(&j.ID, &j.Kind, &j.ResourceID, &j.OwnerID, &domain, &j.State, &j.Attempt, &j.MaxAttempts, &lease, &j.FencingToken, &j.NextRunAt, &j.Completed, &j.Total, &j.ErrorCode, &j.ErrorMessage, &j.CancelRequested, &j.CreatedAt, &j.UpdatedAt, &payload, &checkpoint, &result, &submission)
	if err != nil {
		return j, err
	}
	j.DomainID = domain.String
	j.LeaseOwner = lease.String
	if submission.Valid {
		if err = s.Decrypt("job-context:"+j.ID, submission.String, &j.Submission); err != nil {
			return j, err
		}
	}
	j.Payload, err = s.Box.Open("job-payload:"+j.ID, payload)
	if err != nil {
		return j, err
	}
	if checkpoint.Valid {
		j.Checkpoint, err = s.Box.Open("job-checkpoint:"+j.ID, checkpoint.String)
		if err != nil {
			return j, err
		}
	}
	if result.Valid {
		j.Result, err = s.Box.Open("job-result:"+j.ID, result.String)
	}
	return j, err
}
func (s *Store) Job(ctx context.Context, id string) (Job, error) {
	return s.scanJob(s.DB.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE id=?", id))
}
func (s *Store) Jobs(ctx context.Context, p Principal, limit int) ([]Job, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	query := "SELECT id FROM jobs"
	args := []any{}
	if !p.Admin() {
		query += " WHERE owner_id=?"
		args = append(args, p.User.ID)
	}
	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	jobs := []Job{}
	for _, id := range ids {
		j, e := s.Job(ctx, id)
		if e != nil {
			return nil, e
		}
		jobs = append(jobs, j)
	}
	return jobs, nil
}
func (s *Store) CreateJob(ctx context.Context, j Job) (Job, error) {
	if !json.Valid(j.Payload) {
		return j, errors.New("job payload must be valid JSON")
	}
	if j.IdempotencyKey != "" {
		old, e := s.scanJob(s.DB.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE idempotency_key=?", j.IdempotencyKey))
		if e == nil {
			if old.Kind != j.Kind || old.OwnerID != j.OwnerID || old.ResourceID != j.ResourceID || string(old.Payload) != string(j.Payload) {
				return j, ErrConflict
			}
			return old, nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return j, e
		}
	}
	if j.ResourceID != "" {
		release, e := s.LockResources(ctx, []string{"job-submit:" + j.ResourceID})
		if e != nil {
			return j, e
		}
		defer release()
		var action struct {
			Action string `json:"action"`
		}
		json.Unmarshal(j.Payload, &action)
		// Cancellation, revocation and read-only tests remain available while a
		// resource needs review. Starting another writer cannot bypass recovery.
		if action.Action != "test" && action.Action != "quota" && action.Action != "cancel" && action.Action != "revoke" {
			var unknown, active int
			if e = s.DB.QueryRowContext(ctx, "SELECT COALESCE(SUM(state='unknown'),0),COALESCE(SUM(state IN ('queued','running','retry')),0) FROM jobs WHERE resource_id=?", j.ResourceID).Scan(&unknown, &active); e != nil {
				return j, e
			}
			if unknown > 0 {
				return j, ErrResultUnknown
			}
			if active > 0 {
				return j, ErrResourceBusy
			}
		}
	}
	if j.ID == "" {
		id, err := ID()
		if err != nil {
			return j, err
		}
		j.ID = id
	}
	if j.MaxAttempts < 1 {
		j.MaxAttempts = 3
	}
	if j.NextRunAt.IsZero() {
		j.NextRunAt = time.Now().UTC()
	}
	enc, err := s.Box.Seal("job-payload:"+j.ID, j.Payload)
	if err != nil {
		return j, err
	}
	var contextCipher any
	if j.Submission != nil {
		contextCipher, err = s.Encrypt("job-context:"+j.ID, j.Submission)
		if err != nil {
			return j, err
		}
	}
	_, err = s.DB.ExecContext(ctx, "INSERT INTO jobs (id,kind,resource_id,owner_id,domain_id,payload_ciphertext,max_attempts,next_run_at,idempotency_key,occurrence_key,total,context_ciphertext,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))", j.ID, j.Kind, j.ResourceID, j.OwnerID, nullString(j.DomainID), enc, j.MaxAttempts, j.NextRunAt, nullString(j.IdempotencyKey), nullString(j.OccurrenceKey), j.Total, contextCipher)
	if err != nil {
		if IsDuplicate(err) && j.IdempotencyKey != "" {
			old, e := s.scanJob(s.DB.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE idempotency_key=?", j.IdempotencyKey))
			if e != nil {
				return j, e
			}
			if old.Kind != j.Kind || old.OwnerID != j.OwnerID || old.ResourceID != j.ResourceID || string(old.Payload) != string(j.Payload) {
				return j, ErrConflict
			}
			return old, nil
		}
		return j, err
	}
	return s.Job(ctx, j.ID)
}
func (s *Store) ClaimJob(ctx context.Context, worker string, lease time.Duration) (Job, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback()
	var id, state string
	// An abandoned running job is reconciled by its handler using the saved checkpoint.
	err = tx.QueryRowContext(ctx, "SELECT id,state FROM jobs WHERE ((state IN ('queued','retry') AND next_run_at<=UTC_TIMESTAMP(6)) OR (state='running' AND lease_until<UTC_TIMESTAMP(6))) AND cancel_requested=FALSE ORDER BY next_run_at,id LIMIT 1 FOR UPDATE SKIP LOCKED").Scan(&id, &state)
	if err != nil {
		return Job{}, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE jobs SET state='running',lease_owner=?,lease_until=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL ? SECOND),fencing_token=fencing_token+1,attempt=attempt+1,updated_at=UTC_TIMESTAMP(6) WHERE id=?", worker, int(lease.Seconds()), id)
	if err != nil {
		return Job{}, err
	}
	if err = tx.Commit(); err != nil {
		return Job{}, err
	}
	return s.Job(ctx, id)
}
func (s *Store) LeaseJob(ctx context.Context, j Job, lease time.Duration) error {
	result, err := s.DB.ExecContext(ctx, "UPDATE jobs SET lease_until=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL ? SECOND),updated_at=UTC_TIMESTAMP(6) WHERE id=? AND state='running' AND lease_owner=? AND fencing_token=? AND lease_until>UTC_TIMESTAMP(6)", int(lease.Seconds()), j.ID, j.LeaseOwner, j.FencingToken)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrLeaseLost
	}
	return nil
}
func (s *Store) CheckpointJob(ctx context.Context, j Job, data any) error {
	enc, err := s.Encrypt("job-checkpoint:"+j.ID, data)
	if err != nil {
		return err
	}
	result, err := s.DB.ExecContext(ctx, "UPDATE jobs SET checkpoint_ciphertext=?,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND state='running' AND lease_owner=? AND fencing_token=? AND lease_until>UTC_TIMESTAMP(6)", enc, j.ID, j.LeaseOwner, j.FencingToken)
	return leaseResult(result, err)
}
func leaseResult(r sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrLeaseLost
	}
	return nil
}
func (s *Store) CompleteJob(ctx context.Context, j Job, state string, result any, code, message string, next time.Time) error {
	switch state {
	case "succeeded", "partial", "failed", "unknown", "cancelled", "retry":
	default:
		return errors.New("invalid job terminal state")
	}
	enc, err := s.Encrypt("job-result:"+j.ID, result)
	if err != nil {
		return err
	}
	if next.IsZero() {
		next = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE jobs SET state=?,result_ciphertext=?,error_code=?,error_message=?,next_run_at=?,lease_owner=NULL,lease_until=NULL,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND state='running' AND lease_owner=? AND fencing_token=? AND lease_until>UTC_TIMESTAMP(6)", state, enc, code, truncate(message, 1024), next, j.ID, j.LeaseOwner, j.FencingToken)
	if err = leaseResult(res, err); err != nil {
		return err
	}
	// Waiting for another live writer is scheduling contention, not a failed
	// remote attempt. It must not consume the normal executor retry budget.
	if state == "retry" && (code == "resource_busy" || code == "window_wait") {
		if _, err = tx.ExecContext(ctx, "UPDATE jobs SET attempt=GREATEST(attempt-1,0) WHERE id=?", j.ID); err != nil {
			return err
		}
	}
	// Probe completion is routine; monitor transition events are emitted with
	// the state change. Notification tests cannot recursively notify themselves.
	if state != "retry" && state != "cancelled" && j.Kind != "notification_channels" && !(j.Kind == "monitors" && state == "succeeded") {
		eventName := "job." + state
		if j.Kind == "certificates" {
			eventName = "certificate.failed"
			if state == "succeeded" {
				eventName = "certificate.issued"
				var payload map[string]any
				json.Unmarshal(j.Payload, &payload)
				if payload["action"] == "cancel" || payload["action"] == "revoke" {
					eventName = "certificate." + fmt.Sprint(payload["action"])
				}
			}
		}
		if j.Kind == "deployments" {
			eventName = "deployment.failed"
			if state == "succeeded" {
				eventName = "deployment.succeeded"
			}
		}
		event := notifications.Message{Title: fmt.Sprintf("%s任务%s", j.Kind, state), Body: "请在任务中心查看执行详情。", Event: eventName, ResourceID: j.ResourceID, Data: map[string]any{"job_id": j.ID}}
		if err = s.insertBusinessEvent(ctx, tx, "job:"+j.ID, event); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) CancelJob(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, "UPDATE jobs SET cancel_requested=TRUE,state=IF(state IN ('queued','retry'),'cancelled',state),updated_at=UTC_TIMESTAMP(6) WHERE id=? AND state IN ('queued','retry','running')", id)
	return err
}
func (s *Store) AddJobEvent(ctx context.Context, j Job, level, message string, data any) error {
	// Validate the lease before recording events from an executor; empty lease is a submitter event.
	if j.LeaseOwner != "" {
		var n int
		err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM jobs WHERE id=? AND state='running' AND lease_owner=? AND fencing_token=? AND lease_until>UTC_TIMESTAMP(6)", j.ID, j.LeaseOwner, j.FencingToken).Scan(&n)
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrLeaseLost
		}
	}
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, "INSERT INTO job_events (job_id,level,message,data,created_at) VALUES (?,?,?,?,UTC_TIMESTAMP(6))", j.ID, level, truncate(message, 2048), b)
	return err
}
func (s *Store) JobEvents(ctx context.Context, id string, after int64) ([]JobEvent, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id,job_id,level,message,data,created_at FROM job_events WHERE job_id=? AND id>? ORDER BY id LIMIT 200", id, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []JobEvent{}
	for rows.Next() {
		var event JobEvent
		var n int64
		var data []byte
		if err = rows.Scan(&n, &event.JobID, &event.Level, &event.Message, &data, &event.CreatedAt); err != nil {
			return nil, err
		}
		event.Data = data
		event.ID = fmt.Sprint(n)
		events = append(events, event)
	}
	return events, rows.Err()
}
func (s *Store) SaveJobItem(ctx context.Context, j Job, item JobItem) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRowContext(ctx, "SELECT fencing_token FROM jobs WHERE id=? AND state='running' AND lease_owner=? AND lease_until>UTC_TIMESTAMP(6) FOR UPDATE", j.ID, j.LeaseOwner).Scan(&current)
	if err != nil {
		return err
	}
	if current != j.FencingToken {
		return ErrLeaseLost
	}
	enc, err := s.Box.Seal(fmt.Sprintf("job-item:%s:%d", j.ID, item.Index), item.Detail)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO job_items (job_id,item_index,resource_id,state,detail_ciphertext,updated_at) VALUES (?,?,?,?,?,UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE state=VALUES(state),detail_ciphertext=VALUES(detail_ciphertext),updated_at=UTC_TIMESTAMP(6)", j.ID, item.Index, item.ResourceID, item.State, enc)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE jobs SET completed=(SELECT COUNT(*) FROM job_items WHERE job_id=? AND state IN ('succeeded','failed','unknown','skipped')),updated_at=UTC_TIMESTAMP(6) WHERE id=?", j.ID, j.ID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) JobItems(ctx context.Context, id string) ([]JobItem, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT item_index,resource_id,state,detail_ciphertext FROM job_items WHERE job_id=? ORDER BY item_index", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []JobItem{}
	for rows.Next() {
		var item JobItem
		var enc sql.NullString
		if err = rows.Scan(&item.Index, &item.ResourceID, &item.State, &enc); err != nil {
			return nil, err
		}
		if enc.Valid {
			item.Detail, err = s.Box.Open(fmt.Sprintf("job-item:%s:%d", id, item.Index), enc.String)
			if err != nil {
				return nil, err
			}
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
