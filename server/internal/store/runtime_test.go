package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestRuntimeVersionFencingAndTransactionalEvent(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	o, err := s.SaveObject(ctx, Object{Kind: "monitors", Name: "runtime fixture", OwnerID: "fixture", Active: true, Data: json.RawMessage(`{"frequency_seconds":60,"legacy":{"preserved":true},"state":{}}`)}, true)
	if err != nil {
		t.Fatal(err)
	}
	j, err := s.CreateJob(ctx, Job{Kind: "monitors", OwnerID: "fixture", ResourceID: o.ID, Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.DB.Exec("DELETE FROM business_events WHERE event_key=?", "runtime:"+j.ID)
		s.DB.Exec("DELETE FROM jobs WHERE id=?", j.ID)
		s.DB.Exec("DELETE FROM objects WHERE id=?", o.ID)
	})
	j, err = s.ClaimJob(ctx, "runtime-fixture-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := s.SaveObjectRuntime(ctx, o, j, map[string]any{"state": map[string]bool{"healthy": true}}, "runtime:"+j.ID, map[string]any{"event": "monitor.recovery"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ConfigVersion != o.ConfigVersion || updated.Version <= o.Version {
		t.Fatal("runtime changed configuration revision")
	}
	var data map[string]any
	json.Unmarshal(updated.Data, &data)
	if data["legacy"] == nil || data["frequency_seconds"] != float64(60) {
		t.Fatal("unknown configuration lost", data)
	}
	var count int
	s.DB.QueryRow("SELECT COUNT(*) FROM business_events WHERE event_key=?", "runtime:"+j.ID).Scan(&count)
	if count != 1 {
		t.Fatal("state event missing")
	}
	updated.Name = "new configuration"
	updated, err = s.SaveObject(ctx, updated, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveObjectRuntime(ctx, o, j, map[string]any{"state": nil}, "", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("stale config accepted", err)
	}
	s.DB.Exec("UPDATE jobs SET fencing_token=fencing_token+1 WHERE id=?", j.ID)
	if _, err = s.SaveObjectRuntime(ctx, updated, j, map[string]any{"state": nil}, "runtime-stale:"+j.ID, nil); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale worker state accepted", err)
	}
	s.DB.QueryRow("SELECT COUNT(*) FROM business_events WHERE event_key=?", "runtime-stale:"+j.ID).Scan(&count)
	if count != 0 {
		t.Fatal("failed state write committed event")
	}
}

func TestBusinessEventFanoutAndNotificationFence(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	suffix, _ := ID()
	eventKey := "fixture-event:" + suffix
	if err := s.QueueBusinessEvent(ctx, eventKey, map[string]any{"event": "test", "content": "fixture"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.DB.Exec("DELETE FROM business_events WHERE event_key=?", eventKey)
		s.DB.Exec("DELETE FROM notification_outbox WHERE event_key IN (?,?)", eventKey+":channel-a", eventKey+":channel-b")
	})
	broken := errors.New("fanout unavailable")
	if err := s.DispatchOneEvent(ctx, func(json.RawMessage) ([]string, error) { return nil, broken }); err != broken {
		t.Fatal(err)
	}
	var pending int
	s.DB.QueryRow("SELECT COUNT(*) FROM business_events WHERE event_key=? AND dispatched_at IS NULL", eventKey).Scan(&pending)
	if pending != 1 {
		t.Fatal("failed dispatch lost event")
	}
	// The preceding runtime test deliberately retained an undelivered event;
	// dispatch all isolated pending fixtures before claiming the matching notice.
	for n := 0; n < 10000; n++ {
		err := s.DispatchOneEvent(ctx, func(raw json.RawMessage) ([]string, error) {
			var d map[string]any
			json.Unmarshal(raw, &d)
			if d["event"] == "test" {
				return []string{"channel-a", "channel-b"}, nil
			}
			return nil, nil
		})
		if err != nil {
			break
		}
		if e := s.DB.QueryRow("SELECT COUNT(*) FROM business_events WHERE event_key=? AND dispatched_at IS NULL", eventKey).Scan(&pending); e != nil {
			t.Fatal(e)
		}
		if pending == 0 {
			break
		}
	}
	s.DB.QueryRow("SELECT COUNT(*) FROM notification_outbox WHERE event_key IN (?,?)", eventKey+":channel-a", eventKey+":channel-b").Scan(&pending)
	if pending != 2 {
		t.Fatal("fanout not durable", pending)
	}
	first, err := s.ClaimNotification(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.DB.Exec("UPDATE notification_outbox SET next_run_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND) WHERE id=?", first.ID)
	second, err := s.ClaimNotification(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.FencingToken <= first.FencingToken {
		t.Fatal("notification fence not advanced")
	}
	if err = s.FinishNotification(ctx, first, "sent", 0); err != ErrLeaseLost {
		t.Fatal("stale notification ack", err)
	}
	if err = s.FinishNotification(ctx, second, "sent", 0); err != nil {
		t.Fatal(err)
	}
}
