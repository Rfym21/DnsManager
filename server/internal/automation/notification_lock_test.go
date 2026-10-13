package automation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/dns-manager/dnsmgr/server/internal/notifications"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestNotificationDeliveryHonorsChannelWriterLock(t *testing.T) {
	s := workerStore(t)
	u := workerUser(t, s)
	ctx := context.Background()
	var calls atomic.Int64
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer remote.Close()
	raw, _ := json.Marshal(notifications.Channel{Provider: "custom_webhook", Config: map[string]string{"url": remote.URL, "method": "POST", "body_template": "{{content}}", "content_type": "text/plain"}})
	object, err := s.SaveObject(ctx, store.Object{Kind: "notification_channels", OwnerID: u.ID, Name: "writer lock fixture", Active: true, Data: raw}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.DB.Exec("DELETE FROM notification_outbox WHERE channel_id=?", object.ID)
		s.DB.Exec("DELETE FROM objects WHERE id=?", object.ID)
	})
	if err = s.EnqueueNotification(ctx, "writer-lock:"+object.ID, object.ID, notifications.Message{Event: "fixture", Body: "fixture"}); err != nil {
		t.Fatal(err)
	}
	r := &Runner{Store: s}
	release, err := s.LockResources(ctx, []string{"object:" + object.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.DeliverNotifications(ctx); err != nil || calls.Load() != 0 {
		release()
		t.Fatal("notification bypassed active channel writer", err, calls.Load())
	}
	release()
	if _, err = s.DB.Exec("UPDATE notification_outbox SET next_run_at=UTC_TIMESTAMP(6) WHERE channel_id=?", object.ID); err != nil {
		t.Fatal(err)
	}
	if err = r.DeliverNotifications(ctx); err != nil || calls.Load() != 1 {
		t.Fatal("released channel did not deliver", err, calls.Load())
	}
	if err = r.DeliverNotifications(ctx); err != nil || calls.Load() != 1 {
		t.Fatal("sent notification delivered again", err, calls.Load())
	}
}
