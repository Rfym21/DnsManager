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

	deployprovider "github.com/dns-manager/dnsmgr/server/internal/providers/deploy"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestDeploymentSubmitMarkerSurvivesProviderCheckpoint(t *testing.T) {
	pending := deploymentPendingInfo(deployprovider.Info{"certificate_id": "remote-9"}, "job-1", "fingerprint-1")
	if !deploymentSubmissionPending(pending) {
		t.Fatal("deployment submission is replayable after crash")
	}
	next := deploymentPendingInfo(deployprovider.Info{"certificate_id": "remote-10"}, "job-1", "fingerprint-1")
	if !deploymentSubmissionPending(next) || next["certificate_id"] != "remote-10" {
		t.Fatal("provider checkpoint discarded pending marker or remote ID")
	}
	complete := deploymentCompleteInfo(next, "job-1", "fingerprint-1")
	if deploymentSubmissionPending(complete) || deploymentCompletedResult(complete, "job-1", "fingerprint-1") == nil {
		t.Fatal("confirmed completion is not recoverable")
	}
	if deploymentCompletedResult(complete, "job-2", "fingerprint-1") != nil || deploymentCompletedResult(complete, "job-1", "fingerprint-2") != nil {
		t.Fatal("completion crossed job or certificate generation")
	}
	clean := deploymentClearMarkers(pending)
	if deploymentSubmissionPending(clean) || clean["certificate_id"] != "remote-9" {
		t.Fatal("confirmed rejection did not preserve receipt while clearing marker")
	}
}

func TestDeploymentCrashSubmissionPreventsRemoteReplay(t *testing.T) {
	s := workerStore(t)
	user := workerUser(t, s)
	ctx := context.Background()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "example.invalid"}, DNSNames: []string{"example.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	rawKey, _ := x509.MarshalPKCS8PrivateKey(private)
	save := func(kind string, data any) store.Object {
		raw, _ := json.Marshal(data)
		object, err := s.SaveObject(ctx, store.Object{Kind: kind, OwnerID: user.ID, Name: "deployment crash fixture", Data: raw, Active: true}, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.DB.Exec("DELETE FROM objects WHERE id=?", object.ID) })
		return object
	}
	certificate := save("certificates", CertificateData{Status: "issued", Domains: []string{"example.invalid"}, Fullchain: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey})), Fingerprint: "generation-1"})
	var calls atomic.Int64
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(`{"status":true}`)) }))
	defer remote.Close()
	account := save("deploy_accounts", DeployAccountData{Provider: "btpanel", Config: map[string]string{"url": remote.URL, "key": "fixture-secret"}})
	deployment := save("deployments", DeploymentData{AccountID: account.ID, CertificateID: certificate.ID, Target: map[string]string{"type": "1"}})
	job, err := s.CreateJob(ctx, store.Job{Kind: "deployments", ResourceID: deployment.ID, OwnerID: user.ID, Payload: []byte(`{"action":"execute"}`)})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimJob(ctx, "crashed-worker", 30*time.Second)
	if err != nil || claimed.ID != job.ID {
		t.Fatal(err)
	}
	marker := deploymentPendingInfo(deployprovider.Info{"certificate_id": "remote-9"}, job.ID, "generation-1")
	if err = s.CheckpointJob(ctx, claimed, marker); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveObjectRuntime(ctx, deployment, claimed, map[string]any{"info": marker}, "", nil); err != nil {
		t.Fatal(err)
	}
	// Simulate the process dying after the remote request, before completion.
	s.DB.Exec("UPDATE jobs SET lease_until=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND) WHERE id=?", job.ID)
	reclaimed, err := s.ClaimJob(ctx, "replacement-worker", 30*time.Second)
	if err != nil || reclaimed.ID != job.ID {
		t.Fatal(err)
	}
	runner := &Runner{Store: s}
	worker := Worker{Store: s, Lease: 30 * time.Second, Handlers: runner.CertificateHandlers()}
	worker.execute(ctx, reclaimed)
	current, err := s.Job(ctx, job.ID)
	if err != nil || current.State != "unknown" || calls.Load() != 0 {
		t.Fatal("crashed submission was replayed", current.State, calls.Load(), err)
	}
	// The object marker also protects a later job even if the old terminal job
	// was removed by an administrator or imported from a previous worker.
	s.DB.Exec("UPDATE jobs SET state='failed' WHERE id=?", job.ID)
	newJob, err := s.CreateJob(ctx, store.Job{Kind: "deployments", ResourceID: deployment.ID, OwnerID: user.ID, Payload: []byte(`{"action":"execute"}`)})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = s.ClaimJob(ctx, "new-job-worker", 30*time.Second)
	if err != nil || claimed.ID != newJob.ID {
		t.Fatal(err)
	}
	worker.execute(ctx, claimed)
	current, _ = s.Job(ctx, newJob.ID)
	if current.State != "unknown" || calls.Load() != 0 {
		t.Fatal("new job bypassed object submission marker", current.State, calls.Load())
	}
}
