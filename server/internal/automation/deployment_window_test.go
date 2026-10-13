package automation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestDeploymentWindowTimezoneAndCrossMidnight(t *testing.T) {
	window := DeploymentWindow{Enabled: true, Timezone: "Asia/Shanghai", Start: "23:00", End: "02:00", Weekdays: []int{1}}
	loc, _ := time.LoadLocation(window.Timezone)
	parse := func(value string) time.Time {
		date, err := time.ParseInLocation("2006-01-02 15:04", value, loc)
		if err != nil {
			t.Fatal(err)
		}
		return date
	}
	for _, tt := range []struct{ now, next string }{
		{"2026-10-12 22:59", "2026-10-12 23:00"},
		{"2026-10-12 23:00", "2026-10-12 23:00"},
		{"2026-10-13 01:59", "2026-10-13 01:59"},
		{"2026-10-13 02:00", "2026-10-19 23:00"},
		{"2026-10-14 01:00", "2026-10-19 23:00"},
	} {
		next, err := deploymentWindowNext(window, parse(tt.now).UTC())
		if err != nil || !next.Equal(parse(tt.next)) {
			t.Errorf("now=%s next=%s want=%s err=%v", tt.now, next, tt.next, err)
		}
	}
	window.Start, window.End = "09:00", "17:00"
	if next, err := deploymentWindowNext(window, parse("2026-10-12 16:59")); err != nil || !next.Equal(parse("2026-10-12 16:59")) {
		t.Fatal("same-day window rejected", next, err)
	}
	if next, err := deploymentWindowNext(window, parse("2026-10-12 17:00")); err != nil || !next.Equal(parse("2026-10-19 09:00")) {
		t.Fatal("window end must be exclusive", next, err)
	}
	for _, edit := range []func(*DeploymentWindow){
		func(w *DeploymentWindow) { w.Timezone = "invalid" },
		func(w *DeploymentWindow) { w.Start = "9:00" },
		func(w *DeploymentWindow) { w.Start = "24:00" },
		func(w *DeploymentWindow) { w.Start = w.End },
		func(w *DeploymentWindow) { w.Weekdays = nil },
		func(w *DeploymentWindow) { w.Weekdays = []int{1, 1} },
		func(w *DeploymentWindow) { w.Weekdays = []int{7} },
	} {
		bad := window
		edit(&bad)
		if ValidateDeploymentWindow(bad) == nil {
			t.Fatal("invalid deployment window accepted", bad)
		}
	}
	policy, err := NormalizeDeploymentRetryPolicy(DeploymentRetryPolicy{})
	if err != nil || policy.MaxAttempts != 3 || policy.DelaySeconds != 60 {
		t.Fatal("retry defaults lost", policy, err)
	}
	for _, policy := range []DeploymentRetryPolicy{{MaxAttempts: -1}, {MaxAttempts: 11}, {DelaySeconds: 4}, {DelaySeconds: 86401}} {
		if _, err = NormalizeDeploymentRetryPolicy(policy); err == nil {
			t.Fatal("invalid retry policy accepted", policy)
		}
	}
}

func TestDeploymentWindowWaitDoesNotConsumeAttempt(t *testing.T) {
	s := workerStore(t)
	u := workerUser(t, s)
	ctx := context.Background()
	now := time.Now().UTC()
	tomorrow := now.AddDate(0, 0, 1)
	window := DeploymentWindow{Enabled: true, Timezone: "UTC", Start: "12:00", End: "13:00", Weekdays: []int{int(tomorrow.Weekday())}}
	raw, _ := json.Marshal(DeploymentData{Window: window, RetryPolicy: DeploymentRetryPolicy{MaxAttempts: 1, DelaySeconds: 5}})
	object, err := s.SaveObject(ctx, store.Object{Kind: "deployments", OwnerID: u.ID, Name: "window fixture", Active: true, Data: raw}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.DB.Exec("DELETE FROM objects WHERE id=?", object.ID)
	})
	job, err := s.CreateJob(ctx, store.Job{Kind: "deployments", ResourceID: object.ID, OwnerID: u.ID, Payload: []byte(`{"action":"deploy"}`), MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimJob(ctx, "window-fixture", 30*time.Second)
	if err != nil || claimed.ID != job.ID {
		t.Fatal("window fixture claim", err)
	}
	r := &Runner{Store: s}
	_, err = r.deployment(ctx, claimed)
	var deferred *DeferredError
	if !errors.As(err, &deferred) || !deferred.Until.After(now) {
		t.Fatal("closed window did not defer before resolving credentials", err)
	}
	w := Worker{Store: s, Lease: 30 * time.Second, Handlers: r.CertificateHandlers()}
	w.execute(ctx, claimed)
	completed, err := s.Job(ctx, job.ID)
	if err != nil || completed.State != "retry" || completed.ErrorCode != "window_wait" || completed.Attempt != 0 || !completed.NextRunAt.After(now) {
		t.Fatalf("window consumed attempt: %+v err=%v", completed, err)
	}
	var events int
	s.DB.QueryRow("SELECT COUNT(*) FROM business_events WHERE event_key=?", "job:"+job.ID).Scan(&events)
	if events != 0 {
		t.Fatal("window wait emitted a terminal failure notification")
	}
}
