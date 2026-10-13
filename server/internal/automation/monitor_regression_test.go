package automation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestConditionalMonitorTestEvaluatesDependenciesWithoutNetworkProbe(t *testing.T) {
	s := workerStore(t)
	u := workerUser(t, s)
	ctx := context.Background()
	healthy := true
	raw, _ := json.Marshal(MonitorData{State: MonitorState{Healthy: &healthy, LastProbe: ProbeResult{CheckedAt: time.Now().UTC()}}})
	dependency, err := s.SaveObject(ctx, store.Object{Kind: "monitors", OwnerID: u.ID, Name: "healthy dependency", Active: true, Data: raw}, true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(MonitorData{Mode: "conditional", ConditionIDs: []string{dependency.ID}, ConditionThreshold: 0, ProbeSpec: ProbeSpec{Proxy: true}})
	object, err := s.SaveObject(ctx, store.Object{Kind: "monitors", OwnerID: u.ID, Name: "conditional fixture", Active: true, Data: raw}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Exec("DELETE FROM objects WHERE id IN (?,?)", object.ID, dependency.ID) })
	r := Runner{Store: s}
	job := store.Job{ResourceID: object.ID, OwnerID: u.ID, Payload: json.RawMessage(`{"action":"test"}`)}
	result, err := r.monitor(ctx, job)
	if err != nil || !result.(ProbeResult).Healthy || result.(ProbeResult).Error != "" {
		t.Fatal(result, err)
	}
	stale, _ := json.Marshal(MonitorData{State: MonitorState{Healthy: &healthy, LastProbe: ProbeResult{CheckedAt: time.Now().Add(-time.Hour)}}})
	enc, _ := s.Box.Seal("object:"+dependency.ID, stale)
	s.DB.Exec("UPDATE objects SET data_ciphertext=? WHERE id=?", enc, dependency.ID)
	result, err = r.monitor(ctx, job)
	if err != nil || result.(ProbeResult).Healthy {
		t.Fatal("stale dependency counted healthy", result, err)
	}
	if _, err = s.DB.Exec("UPDATE objects SET active=FALSE WHERE id=?", dependency.ID); err != nil {
		t.Fatal(err)
	}
	result, err = r.monitor(ctx, job)
	if err != nil || result.(ProbeResult).Healthy {
		t.Fatal("inactive dependency counted healthy", result, err)
	}
}
