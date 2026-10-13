package automation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	certprovider "github.com/dns-manager/dnsmgr/server/internal/providers/cert"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestCertificateCancellationCleansCrashIntentWithoutIssuerReceipt(t *testing.T) {
	s := workerStore(t)
	u := workerUser(t, s)
	ctx := context.Background()
	account, err := s.SaveAccount(ctx, store.Account{Name: "cancel DNS fixture", Provider: "cloudflare", Config: map[string]string{"api_token": "fixture"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := s.AddDomain(ctx, store.Domain{AccountID: account.ID, Name: "example.invalid", ASCIIName: "example.invalid", ProviderDomainID: "fixture-zone"})
	if err != nil {
		t.Fatal(err)
	}
	object, err := s.SaveObject(ctx, store.Object{Kind: "certificates", Name: "cancel fixture", OwnerID: u.ID, Data: json.RawMessage(`{}`)}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.DB.Exec("DELETE FROM objects WHERE id=?", object.ID)
		s.DB.Exec("DELETE FROM domains WHERE id=?", domain.ID)
		s.DB.Exec("DELETE FROM provider_accounts WHERE id=?", account.ID)
	})
	job, err := s.CreateJob(ctx, store.Job{Kind: "certificates", OwnerID: u.ID, ResourceID: object.ID, Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	job, err = s.ClaimJob(ctx, "cancel-fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	provider := &challengeFixtureProvider{interrupt: true}
	r := &Runner{Store: s, DNSFactory: func(string, map[string]string, string, string) (dns.Provider, error) { return provider, nil }, LookupCNAME: func(_ context.Context, name string) (string, error) { return name, nil }}
	callback := &challengeDNS{runner: r, job: job}
	challenge := certprovider.Challenge{Domain: domain.ASCIIName, Name: "_acme-challenge.example.invalid", Type: "TXT", Value: "crash-value"}
	if _, err = callback.Present(ctx, challenge); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("fixture write did not interrupt before receipt", err)
	}
	// No cp.Receipt or cp.Presented was saved. Cancellation must still find
	// the submitted intent without depending on the interrupted provider call.
	if err = callback.cleanupResourceIntents(ctx); err != nil || provider.deletes != 1 || len(provider.records) != 0 {
		t.Fatal("cancel left its crash-created TXT behind", err, provider.deletes)
	}
	if err = callback.cleanupResourceIntents(ctx); err != nil || provider.deletes != 1 {
		t.Fatal("cancel cleanup is not resumable", err)
	}
	var state string
	if err = s.DB.QueryRow("SELECT state FROM dns_challenge_intents WHERE job_id=?", job.ID).Scan(&state); err != nil || state != "cleaned" {
		t.Fatal("cancel cleanup state was not checkpointed", state, err)
	}
}
