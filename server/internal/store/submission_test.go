package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUnknownResourceCannotStartAnotherWriterButAllowsRecoveryActions(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	id, _ := ID()
	j, e := s.CreateJob(ctx, Job{Kind: "deployments", OwnerID: "fixture", ResourceID: id, Payload: []byte(`{"action":"execute"}`), IdempotencyKey: "fence:" + id})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Exec("DELETE FROM jobs WHERE resource_id=?", id) })
	j, e = s.ClaimJob(ctx, "fence", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteJob(ctx, j, "unknown", nil, "result_unknown", "", time.Time{}); e != nil {
		t.Fatal(e)
	}
	_, e = s.CreateJob(ctx, Job{Kind: j.Kind, OwnerID: j.OwnerID, ResourceID: id, Payload: j.Payload})
	if !errors.Is(e, ErrResultUnknown) {
		t.Fatal("new intent bypassed unknown", e)
	}
	again, e := s.CreateJob(ctx, Job{Kind: j.Kind, OwnerID: j.OwnerID, ResourceID: id, Payload: j.Payload, IdempotencyKey: "fence:" + id})
	if e != nil || again.ID != j.ID {
		t.Fatal("idempotent replay lost", e)
	}
	for _, action := range []string{"cancel", "revoke", "test"} {
		if _, e = s.CreateJob(ctx, Job{Kind: j.Kind, OwnerID: j.OwnerID, ResourceID: id, Payload: []byte(`{"action":"` + action + `"}`)}); e != nil {
			t.Fatal(action, e)
		}
	}
}
