package automation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

type runtimeProvider struct {
	challengeFixtureProvider
	updates int
}

func (p *runtimeProvider) Descriptor() dns.Descriptor { return dns.Descriptor{ID: "cloudflare"} }
func (p *runtimeProvider) UpdateRecord(_ context.Context, id string, record dns.Record) (dns.Record, error) {
	p.updates++
	for i, r := range p.records {
		if r.ID == id {
			record.ID = id + "-new"
			p.records[i] = record
			if p.interrupt {
				return dns.Record{}, context.DeadlineExceeded
			}
			return record, nil
		}
	}
	return dns.Record{}, dns.ErrNotFound
}

func runtimeFixture(t *testing.T) (*store.Store, store.User, store.Domain, *runtimeProvider, *Runner) {
	t.Helper()
	s := workerStore(t)
	u := workerUser(t, s)
	ctx := context.Background()
	a, e := s.SaveAccount(ctx, store.Account{Name: "runtime fixture", Provider: "cloudflare", Config: map[string]string{"api_token": "fixture"}}, true)
	if e != nil {
		t.Fatal(e)
	}
	d, e := s.AddDomain(ctx, store.Domain{AccountID: a.ID, Name: "runtime.invalid", ASCIIName: "runtime.invalid", ProviderDomainID: "fixture"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		s.DB.Exec("DELETE FROM domains WHERE id=?", d.ID)
		s.DB.Exec("DELETE FROM provider_accounts WHERE id=?", a.ID)
	})
	p := &runtimeProvider{challengeFixtureProvider: challengeFixtureProvider{records: []dns.Record{{ID: "old", Name: "www", Type: "A", Value: "192.0.2.1", Line: "default", TTL: 300, Enabled: true}}}}
	r := &Runner{Store: s, DNSFactory: func(string, map[string]string, string, string) (dns.Provider, error) { return p, nil }}
	return s, u, d, p, r
}
func runtimeObject(t *testing.T, s *store.Store, u store.User, d store.Domain, kind string, data any) store.Object {
	t.Helper()
	raw, _ := json.Marshal(data)
	o, e := s.SaveObject(context.Background(), store.Object{Kind: kind, Name: "fixture", OwnerID: u.ID, DomainID: d.ID, Active: true, Data: raw}, true)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		s.DB.Exec("DELETE FROM jobs WHERE resource_id=?", o.ID)
		s.DB.Exec("DELETE FROM objects WHERE id=?", o.ID)
	})
	return o
}
func runtimeJob(t *testing.T, s *store.Store, u store.User, o store.Object) store.Job {
	t.Helper()
	j, e := s.CreateJob(context.Background(), store.Job{Kind: o.Kind, ResourceID: o.ID, DomainID: o.DomainID, OwnerID: u.ID, Payload: json.RawMessage(`{"action":"execute"}`)})
	if e != nil {
		t.Fatal(e)
	}
	j, e = s.ClaimJob(context.Background(), "runtime", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	return j
}
func reclaimRuntime(t *testing.T, s *store.Store, j store.Job) store.Job {
	t.Helper()
	if _, e := s.DB.Exec("UPDATE jobs SET lease_until=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND) WHERE id=?", j.ID); e != nil {
		t.Fatal(e)
	}
	j, e := s.ClaimJob(context.Background(), "recovery", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	return j
}

func TestScheduleLostResponseObservedWithoutDuplicateAndUpdatesBinding(t *testing.T) {
	s, u, d, p, r := runtimeFixture(t)
	ctx := context.Background()
	o := runtimeObject(t, s, u, d, "schedules", ScheduleData{RecordID: "old", Operation: "update", Record: dns.Record{Value: "192.0.2.2", TTL: 300}})
	j := runtimeJob(t, s, u, o)
	p.interrupt = true
	if _, e := r.schedule(ctx, j); e == nil {
		t.Fatal("lost response accepted")
	}
	p.interrupt = false
	j = reclaimRuntime(t, s, j)
	if _, e := r.schedule(ctx, j); e != nil {
		t.Fatal(e)
	}
	updated, e := s.Object(ctx, o.ID)
	var data ScheduleData
	json.Unmarshal(updated.Data, &data)
	if e != nil || p.updates != 1 || data.RecordID != "old-new" {
		t.Fatal("duplicate write or stale binding", p.updates, data.RecordID, e)
	}
}

func TestMonitorLostResponseRecoversOriginalTransition(t *testing.T) {
	s, u, d, p, r := runtimeFixture(t)
	ctx := context.Background()
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer remote.Close()
	o := runtimeObject(t, s, u, d, "monitors", MonitorData{RecordID: "old", ProbeSpec: ProbeSpec{Protocol: "http", Target: remote.URL}, Mode: "switch", MainValue: "192.0.2.1", BackupValue: "192.0.2.2", Failures: 1})
	j := runtimeJob(t, s, u, o)
	p.interrupt = true
	if _, e := r.monitor(ctx, j); e == nil {
		t.Fatal("lost response accepted")
	}
	p.interrupt = false
	j = reclaimRuntime(t, s, j)
	if _, e := r.monitor(ctx, j); e != nil {
		t.Fatal(e)
	}
	updated, e := s.Object(ctx, o.ID)
	var data MonitorData
	json.Unmarshal(updated.Data, &data)
	if e != nil || p.updates != 1 || data.RecordID != "old-new" || !data.State.Switched || data.State.Observed != "backup" {
		t.Fatal("transition/binding not recovered", data, p.updates, e)
	}
}

func TestOptimizationPlanConvertsCNAMEAfterReadsAndPreservesOtherFamily(t *testing.T) {
	p := &runtimeProvider{challengeFixtureProvider: challengeFixtureProvider{records: []dns.Record{{ID: "alias", Name: "www", Type: "CNAME", Value: "old.invalid", Line: "default", TTL: 300}, {ID: "v6", Name: "www", Type: "AAAA", Value: "2001:db8::1", Line: "default", TTL: 300, Enabled: true}}}}
	cache := map[string][]dns.Record{}
	plan, e := planOptimizationIPs(context.Background(), p, "www", "default", "ipv4", []string{"192.0.2.1"}, 600, cache)
	if e != nil || len(plan) != 1 || plan[0].Operation != "update" || plan[0].Record.ID != "alias" || p.deletes != 0 || p.updates != 0 {
		t.Fatal("planning destructive", plan, e)
	}
	plan, e = planOptimizationIPs(context.Background(), p, "www", "default", "ipv6", []string{"2001:db8::1"}, 600, cache)
	if e != nil || len(plan) != 1 || plan[0].Record.ID != "v6" || plan[0].Record.TTL != 600 {
		t.Fatal("family or TTL mismatch", plan, e)
	}
}

func TestOptimizationCheckpointSurvivesSourceChange(t *testing.T) {
	s, u, d, p, r := runtimeFixture(t)
	ctx := context.Background()
	o := runtimeObject(t, s, u, d, "optimizations", OptimizationData{SourceURL: "http://source.invalid", IPType: "ipv4", RecordNames: []string{"www"}, RecordCount: 1})
	j := runtimeJob(t, s, u, o)
	plan := optimizationPlan{Mutations: []mutationIntent{{Operation: "update", Record: dns.Record{ID: "old", Name: "www", Type: "A", Value: "192.0.2.9", Line: "default", TTL: 300, Enabled: true}}}, Fields: map[string]any{"last_ips": []string{"192.0.2.9"}}, Result: map[string]any{"ips": []string{"192.0.2.9"}}}
	p.interrupt = true
	if _, e := r.executeOptimizationPlan(ctx, j, o, p, plan); e == nil {
		t.Fatal("lost response accepted")
	}
	p.interrupt = false
	j = reclaimRuntime(t, s, j)
	if _, e := r.optimize(ctx, j); e != nil {
		t.Fatal(e)
	}
	if p.updates != 1 {
		t.Fatal("optimization write repeated")
	}
}

func TestSchedulerMissedPolicyAndOccurrenceDedup(t *testing.T) {
	s := workerStore(t)
	u := workerUser(t, s)
	ctx := context.Background()
	for _, policy := range []string{"skip", "run_once"} {
		o := runtimeObject(t, s, u, store.Domain{}, "schedules", map[string]any{})
		rule := Schedule{Mode: "once", Date: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), MissedPolicy: policy}
		r := &Runner{Store: s}
		if e := r.enqueueDue(ctx, o, rule); e != nil {
			t.Fatal(e)
		}
		if e := r.enqueueDue(ctx, o, rule); e != nil {
			t.Fatal(e)
		}
		var n int
		if e := s.DB.QueryRow("SELECT COUNT(*) FROM jobs WHERE resource_id=?", o.ID).Scan(&n); e != nil {
			t.Fatal(e)
		}
		want := 0
		if policy == "run_once" {
			want = 1
		}
		if n != want {
			t.Fatal("missed policy ignored", policy, n)
		}
	}
}

func TestQueuedScheduleRejectsChangedConfigurationBeforeDNSWrite(t *testing.T) {
	s, u, d, p, r := runtimeFixture(t)
	ctx := context.Background()
	o := runtimeObject(t, s, u, d, "schedules", ScheduleData{RecordID: "old", Operation: "update", Record: dns.Record{Value: "192.0.2.8", TTL: 300}})
	payload, _ := json.Marshal(map[string]any{"action": "execute", "scheduled": true, "config_version": o.ConfigVersion})
	j, e := s.CreateJob(ctx, store.Job{Kind: o.Kind, ResourceID: o.ID, DomainID: o.DomainID, OwnerID: u.ID, Payload: payload})
	if e != nil {
		t.Fatal(e)
	}
	o.Active = false
	if _, e = s.SaveObject(ctx, o, false); e != nil {
		t.Fatal(e)
	}
	j, e = s.ClaimJob(ctx, "stale", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.schedule(ctx, j); e == nil || p.updates != 0 {
		t.Fatal("changed/paused queued config wrote DNS", p.updates, e)
	}
}
