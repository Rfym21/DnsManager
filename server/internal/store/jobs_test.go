package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
)

func integrationStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if path := os.Getenv("TEST_DATABASE_DSN_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		dsn = string(b)
	}
	if dsn == "" {
		t.Skip("requires isolated TEST_DATABASE_DSN or TEST_DATABASE_DSN_FILE")
	}
	box, err := cryptobox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), dsn, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestJobLeaseFencingAndIdempotency(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	id, _ := ID()
	j, err := s.CreateJob(ctx, Job{Kind: "lease_test", OwnerID: "fixture-user", ResourceID: id, Payload: []byte("{\"test\":true}"), IdempotencyKey: "lease-test:" + id})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Exec("DELETE FROM jobs WHERE id=?", j.ID) })
	again, err := s.CreateJob(ctx, Job{Kind: j.Kind, OwnerID: j.OwnerID, ResourceID: id, Payload: j.Payload, IdempotencyKey: "lease-test:" + id})
	if err != nil || again.ID != j.ID {
		t.Fatalf("idempotent submit %v %v", again, err)
	}
	_, err = s.CreateJob(ctx, Job{Kind: j.Kind, OwnerID: j.OwnerID, ResourceID: id, Payload: []byte("{\"test\":false}"), IdempotencyKey: "lease-test:" + id})
	if err != ErrConflict {
		t.Fatalf("same key different body: %v", err)
	}
	// Claim only our isolated test queue (test database must not contain live worker jobs).
	claimed, err := s.ClaimJob(ctx, "first-worker", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != j.ID {
		t.Fatalf("unexpected queued job %s", claimed.ID)
	}
	if err = s.CheckpointJob(ctx, claimed, map[string]string{"step": "external-accepted"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("UPDATE jobs SET lease_until=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND) WHERE id=?", j.ID); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := s.ClaimJob(ctx, "second-worker", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.FencingToken <= claimed.FencingToken || string(reclaimed.Checkpoint) != "{\"step\":\"external-accepted\"}" {
		t.Fatal("checkpoint/fence not preserved", reclaimed)
	}
	if err = s.CompleteJob(ctx, claimed, "succeeded", nil, "", "", time.Time{}); err != ErrLeaseLost {
		t.Fatalf("stale worker wrote result: %v", err)
	}
	if err = s.CompleteJob(ctx, reclaimed, "succeeded", map[string]bool{"ok": true}, "", "", time.Time{}); err != nil {
		t.Fatal(err)
	}
}
func TestCancelledQueuedJobNotClaimed(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	j, err := s.CreateJob(ctx, Job{Kind: "cancel_test", OwnerID: "fixture", Payload: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Exec("DELETE FROM jobs WHERE id=?", j.ID)
	if err = s.CancelJob(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	current, err := s.Job(ctx, j.ID)
	if err != nil || current.State != "cancelled" {
		t.Fatal(current, err)
	}
	if _, err = s.ClaimJob(ctx, "worker", 30*time.Second); err != sql.ErrNoRows {
		t.Fatalf("cancelled job claimed %v", err)
	}
}
