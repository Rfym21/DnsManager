package httpapi

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestBatchRecoveryConfirmsObservedWithoutRemoteMutation(t *testing.T) {
	f := newLegacyFixture(t)
	a := f.a
	ctx := context.Background()
	u, token, csrf := testUser(t, a, "admin")
	// Fixture provider exposes exactly one matching record; recovery only reads.
	domain := f.domain.ID
	provider := f.provider
	a.DNSFactory = func(string, map[string]string, string, string) (dns.Provider, error) { return provider, nil }
	page, _ := provider.ListRecords(ctx, dns.ListOptions{})
	payload, _ := json.Marshal(map[string]any{"domain_ids": []string{domain}, "operation": "create", "records": page.Rows})
	j, err := a.Store.CreateJob(ctx, store.Job{Kind: "record_batch", OwnerID: u.ID, DomainID: domain, Payload: payload, Total: 1, Submission: store.Submission(store.Principal{User: u})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Store.DB.Exec("DELETE FROM jobs WHERE id=?", j.ID) })
	j, err = a.Store.ClaimJob(ctx, "recovery-fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Store.SaveJobItem(ctx, j, store.JobItem{Index: 0, State: "unknown", Detail: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if err = a.Store.CompleteJob(ctx, j, "unknown", nil, "result_unknown", "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	w := requestAPI(a, "POST", "/api/v1/jobs/"+j.ID+"/reconcile", token, csrf, map[string]any{})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	items, err := a.Store.JobItems(ctx, j.ID)
	if err != nil || len(items) != 1 || items[0].State != "succeeded" {
		t.Fatal("observation not confirmed", err)
	}
	w = requestAPI(a, "POST", "/api/v1/jobs/"+j.ID+"/retry", token, csrf, map[string]any{})
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	items, _ = a.Store.JobItems(ctx, j.ID)
	if items[0].State != "succeeded" {
		t.Fatal("successful item erased")
	}
	if provider.writes != 0 {
		t.Fatal("recovery mutated supplier")
	}
}

func TestBatchRecoveryKeepsAmbiguousUnknownAndRejectsUnrelatedUser(t *testing.T) {
	f := newLegacyFixture(t)
	a := f.a
	ctx := context.Background()
	u, token, csrf := testUser(t, a, "admin")
	_, other, otherCSRF := testUser(t, a, "restricted")
	a.DNSFactory = func(string, map[string]string, string, string) (dns.Provider, error) { return f.provider, nil }
	payload, _ := json.Marshal(map[string]any{"domain_ids": []string{f.domain.ID}, "operation": "create", "records": []dns.Record{{Name: "www", Type: "A", Value: "192.0.2.99", TTL: 600, Line: "default", Enabled: true}}})
	j, e := a.Store.CreateJob(ctx, store.Job{Kind: "record_batch", OwnerID: u.ID, DomainID: f.domain.ID, Payload: payload, Total: 1, Submission: store.Submission(store.Principal{User: u})})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Store.DB.Exec("DELETE FROM jobs WHERE id=?", j.ID) })
	j, e = a.Store.ClaimJob(ctx, "unknown", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Store.SaveJobItem(ctx, j, store.JobItem{Index: 0, State: "unknown", Detail: json.RawMessage(`{}`)}); e != nil {
		t.Fatal(e)
	}
	if e = a.Store.CompleteJob(ctx, j, "unknown", nil, "result_unknown", "", time.Time{}); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"retry", "reconcile"} {
		w := requestAPI(a, "POST", "/api/v1/jobs/"+j.ID+"/"+action, other, otherCSRF, map[string]any{})
		if w.Code != 403 {
			t.Fatal("unauthorized recovery", action, w.Code)
		}
	}
	w := requestAPI(a, "POST", "/api/v1/jobs/"+j.ID+"/retry", token, csrf, map[string]any{})
	if w.Code != 409 {
		t.Fatal("unknown replay queued", w.Code, w.Body.String())
	}
	items, e := a.Store.JobItems(ctx, j.ID)
	if e != nil || len(items) != 1 || items[0].State != "unknown" || f.provider.writes != 0 {
		t.Fatal("unknown intent changed", e)
	}
}
