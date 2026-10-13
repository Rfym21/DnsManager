package automation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestDeploymentRetryOnlyConfirmedRejectionAndUnknownStaysTerminal(t *testing.T) {
	s := workerStore(t)
	u := workerUser(t, s)
	ctx := context.Background()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.invalid"}, DNSNames: []string{"example.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := x509.MarshalPKCS8PrivateKey(private)
	certificateData := CertificateData{Status: "issued", Domains: []string{"example.invalid"}, Fullchain: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})), Fingerprint: "fixture-generation"}
	raw, _ := json.Marshal(certificateData)
	certificate, err := s.SaveObject(ctx, store.Object{Kind: "certificates", OwnerID: u.ID, Name: "retry certificate", Active: true, Data: raw}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Exec("DELETE FROM objects WHERE id=?", certificate.ID) })
	var status atomic.Int64
	var calls atomic.Int64
	status.Store(http.StatusTooManyRequests)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
		if status.Load() == http.StatusOK {
			w.Write([]byte(`{"code":1000,"data":[]}`))
		} else {
			w.Write([]byte(`{"message":"fixture remote refusal"}`))
		}
	}))
	defer server.Close()
	raw, _ = json.Marshal(DeployAccountData{Provider: "xp", Config: map[string]string{"url": server.URL, "apikey": "fixture-api-key"}})
	account, err := s.SaveObject(ctx, store.Object{Kind: "deploy_accounts", OwnerID: u.ID, Name: "retry account", Active: true, Data: raw}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Exec("DELETE FROM objects WHERE id=?", account.ID) })
	raw, _ = json.Marshal(DeploymentData{AccountID: account.ID, CertificateID: certificate.ID, Target: map[string]string{"type": "1"}, RetryPolicy: DeploymentRetryPolicy{MaxAttempts: 2, DelaySeconds: 5}})
	object, err := s.SaveObject(ctx, store.Object{Kind: "deployments", OwnerID: u.ID, Name: "retry deployment", Active: true, Data: raw}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Exec("DELETE FROM objects WHERE id=?", object.ID) })
	r := &Runner{Store: s}
	w := Worker{Store: s, Lease: 30 * time.Second, Handlers: r.CertificateHandlers()}
	job, err := s.CreateJob(ctx, store.Job{Kind: "deployments", ResourceID: object.ID, OwnerID: u.ID, MaxAttempts: 2, Payload: []byte(`{"action":"deploy"}`)})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimJob(ctx, "retry-fixture", 30*time.Second)
	if err != nil || claimed.ID != job.ID {
		t.Fatal(err)
	}
	before := time.Now()
	w.execute(ctx, claimed)
	completed, err := s.Job(ctx, job.ID)
	if err != nil || completed.State != "retry" || completed.Attempt != 1 || completed.NextRunAt.Sub(before) < 4*time.Second || completed.NextRunAt.Sub(before) > 7*time.Second || calls.Load() != 1 {
		t.Fatalf("confirmed rejection did not honor retry policy: state=%s attempt=%d next=%s calls=%d err=%v", completed.State, completed.Attempt, completed.NextRunAt, calls.Load(), err)
	}
	s.DB.Exec("UPDATE jobs SET next_run_at=UTC_TIMESTAMP(6) WHERE id=?", job.ID)
	claimed, err = s.ClaimJob(ctx, "retry-fixture", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	w.execute(ctx, claimed)
	completed, _ = s.Job(ctx, job.ID)
	if completed.State != "failed" || completed.Attempt != 2 || calls.Load() != 2 {
		t.Fatal("retry maximum not enforced", completed.State, completed.Attempt, calls.Load())
	}
	// A server-side failure may follow a committed remote write. It cannot
	// re-enter the automatic retry queue without a reconciliation contract.
	status.Store(http.StatusInternalServerError)
	job, err = s.CreateJob(ctx, store.Job{Kind: "deployments", ResourceID: object.ID, OwnerID: u.ID, MaxAttempts: 2, Payload: []byte(`{"action":"deploy"}`)})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = s.ClaimJob(ctx, "retry-fixture", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	w.execute(ctx, claimed)
	completed, _ = s.Job(ctx, job.ID)
	if completed.State != "unknown" || completed.ErrorCode != "result_unknown" || calls.Load() != 3 {
		t.Fatal("unconfirmed write entered automatic retry", completed.State, completed.ErrorCode, calls.Load())
	}
}
