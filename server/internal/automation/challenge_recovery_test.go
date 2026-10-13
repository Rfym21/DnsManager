package automation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	certprovider "github.com/dns-manager/dnsmgr/server/internal/providers/cert"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

type challengeFixtureProvider struct {
	dns.Provider
	records          []dns.Record
	creates, deletes int
	interrupt        bool
}

func (p *challengeFixtureProvider) ListRecords(_ context.Context, o dns.ListOptions) (dns.RecordPage, error) {
	if o.Page > 1 {
		return dns.RecordPage{Rows: []dns.Record{}}, nil
	}
	return dns.RecordPage{Total: len(p.records), Rows: append([]dns.Record(nil), p.records...)}, nil
}
func (p *challengeFixtureProvider) MinTTL(context.Context) (int, error) { return 60, nil }
func (p *challengeFixtureProvider) Lines(context.Context) ([]dns.Line, error) {
	return []dns.Line{{ID: "default"}}, nil
}
func (p *challengeFixtureProvider) CreateRecord(_ context.Context, r dns.Record) (dns.Record, error) {
	p.creates++
	r.ID = "fixture-created"
	p.records = append(p.records, r)
	if p.interrupt {
		return dns.Record{}, context.DeadlineExceeded
	}
	return r, nil
}
func (p *challengeFixtureProvider) GetRecord(_ context.Context, id string) (dns.Record, error) {
	for _, r := range p.records {
		if r.ID == id {
			return r, nil
		}
	}
	return dns.Record{}, dns.ErrNotFound
}
func (p *challengeFixtureProvider) DeleteRecord(_ context.Context, id string) error {
	p.deletes++
	for i, r := range p.records {
		if r.ID == id {
			p.records = append(p.records[:i], p.records[i+1:]...)
			return nil
		}
	}
	return dns.ErrNotFound
}

func TestChallengeCrashRecoversIntentWithoutDuplicateAndProtectsChangedValue(t *testing.T) {
	s := workerStore(t)
	u := workerUser(t, s)
	ctx := context.Background()
	account, err := s.SaveAccount(ctx, store.Account{Name: "challenge fixture", Provider: "cloudflare", Config: map[string]string{"api_token": "fixture"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := s.AddDomain(ctx, store.Domain{AccountID: account.ID, Name: "example.invalid", ASCIIName: "example.invalid", ProviderDomainID: "fixture-zone"})
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.SaveObject(ctx, store.Object{Kind: "certificates", Name: "challenge", OwnerID: u.ID, Data: json.RawMessage(`{}`)}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.DB.Exec("DELETE FROM objects WHERE id=?", o.ID)
		s.DB.Exec("DELETE FROM domains WHERE id=?", domain.ID)
		s.DB.Exec("DELETE FROM provider_accounts WHERE id=?", account.ID)
	})
	j, err := s.CreateJob(ctx, store.Job{Kind: "certificates", OwnerID: u.ID, ResourceID: o.ID, Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	j, err = s.ClaimJob(ctx, "challenge-fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	p := &challengeFixtureProvider{interrupt: true}
	r := &Runner{Store: s, DNSFactory: func(string, map[string]string, string, string) (dns.Provider, error) { return p, nil }, LookupCNAME: func(_ context.Context, name string) (string, error) { return name, nil }}
	c := &challengeDNS{runner: r, job: j}
	ch := certprovider.Challenge{Domain: "example.invalid", Name: "_acme-challenge.example.invalid", Type: "TXT", Value: "fixture-txt"}
	if _, err = c.Present(ctx, ch); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("fixture interruption absent", err)
	}
	p.interrupt = false
	receipt, err := c.Present(ctx, ch)
	if err != nil || p.creates != 1 {
		t.Fatal("crash duplicated DNS create", p.creates, err)
	}
	ch.Receipt = receipt
	p.records[0].Value = "someone-else-value"
	if err = c.Cleanup(ctx, ch); err == nil || p.deletes != 0 {
		t.Fatal("cleanup deleted changed value")
	}
	p.records[0].Value = ch.Value
	if err = c.Cleanup(ctx, ch); err != nil || p.deletes != 1 {
		t.Fatal("receipt cleanup missing", err)
	}
	if _, err = c.Present(ctx, ch); err == nil || !strings.Contains(err.Error(), "先前提交") || p.creates != 1 {
		t.Fatal("absent prior intent silently recreated", err)
	}

	// Records that existed before our intent are reused but never deleted.
	ch2 := certprovider.Challenge{Domain: "example.invalid", Name: "_acme-challenge.example.invalid", Type: "TXT", Value: "preexisting"}
	p.records = []dns.Record{{ID: "prior", Name: "_acme-challenge", Type: "TXT", Value: "preexisting", TTL: 60, Line: "default", Enabled: true}}
	ch2.Receipt, err = c.Present(ctx, ch2)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Cleanup(ctx, ch2); err != nil || p.deletes != 1 {
		t.Fatal("preexisting value deleted", err)
	}
}
