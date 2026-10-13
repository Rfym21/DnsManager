package automation

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/notifications"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestCertificateExpiryEligibilityAndGeneration(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	object := store.Object{ID: "manual", Name: "手工证书", Active: true}
	data := CertificateData{Domains: []string{"example.invalid"}, Status: "issued", NotBefore: now.Add(-30 * 24 * time.Hour), NotAfter: now.Add(7 * 24 * time.Hour), Fullchain: "fixture certificate", PrivateKey: "fixture-private-key", Fingerprint: "generation-one"}
	key, message, eligible := certificateExpiryMessage(object, data, now, 7, time.FixedZone("CST", 8*3600))
	if !eligible || message.Event != "certificate.expiring" || message.ResourceID != object.ID || !strings.Contains(message.Body, "2026-10-20 20:00:00 CST") || message.Data["days_remaining"] != 7 {
		t.Fatalf("manual expiry reminder absent: %+v %v", message, eligible)
	}
	raw, _ := json.Marshal(message)
	if strings.Contains(string(raw), data.PrivateKey) || strings.Contains(string(raw), data.Fullchain) {
		t.Fatal("certificate material leaked into notification")
	}
	// A renewal in progress still has a valid old certificate to warn about.
	data.Status = "order_pending"
	secondKey, _, eligible := certificateExpiryMessage(object, data, now.Add(time.Hour), 30, nil)
	if !eligible || secondKey != key {
		t.Fatal("retry or threshold change created another generation notice")
	}
	data.Fingerprint = "generation-two"
	newKey, _, _ := certificateExpiryMessage(object, data, now, 7, nil)
	if newKey == key {
		t.Fatal("newly issued certificate cannot receive its own reminder")
	}
	tests := []struct {
		name string
		edit func(*store.Object, *CertificateData)
	}{
		{"inactive", func(o *store.Object, _ *CertificateData) { o.Active = false }},
		{"unknown expiry", func(_ *store.Object, d *CertificateData) { d.NotAfter = time.Time{} }},
		{"expired", func(_ *store.Object, d *CertificateData) { d.NotAfter = now }},
		{"future validity", func(_ *store.Object, d *CertificateData) { d.NotBefore = now.Add(time.Hour) }},
		{"outside threshold", func(_ *store.Object, d *CertificateData) { d.NotAfter = now.Add(7*24*time.Hour + time.Nanosecond) }},
		{"revoked", func(_ *store.Object, d *CertificateData) { d.Status = "revoked" }},
		{"cancelled", func(_ *store.Object, d *CertificateData) { d.Status = "cancelled" }},
		{"per certificate threshold", func(_ *store.Object, d *CertificateData) { d.RenewBeforeDays = 3 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, d := object, data
			tt.edit(&o, &d)
			if _, _, ok := certificateExpiryMessage(o, d, now, 7, nil); ok {
				t.Fatal("ineligible certificate emitted a reminder")
			}
		})
	}
	data.NotAfter = now.Add(10 * time.Minute)
	_, message, _ = certificateExpiryMessage(object, data, now, 7, nil)
	if message.Data["days_remaining"] != 1 {
		t.Fatal("certificate expiring later today was reported as already expired")
	}
}

func TestCertificateExpiryTransactionalDedupAndGeneration(t *testing.T) {
	s := workerStore(t)
	u := workerUser(t, s)
	ctx := context.Background()
	now := time.Now().UTC()
	data := CertificateData{Domains: []string{"expiry.example.invalid"}, Status: "issued", NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(3 * 24 * time.Hour), Fingerprint: "first"}
	raw, _ := json.Marshal(data)
	object, err := s.SaveObject(ctx, store.Object{Kind: "certificates", Name: "expiry fixture", OwnerID: u.ID, Active: true, Data: raw}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.DB.Exec("DELETE FROM business_events WHERE event_key LIKE ?", "certificate-expiry:"+object.ID+":%")
		s.DB.Exec("DELETE FROM objects WHERE id=?", object.ID)
	})
	r := &Runner{Store: s}
	count := func() int {
		t.Helper()
		var n int
		if e := s.DB.QueryRow("SELECT COUNT(*) FROM business_events WHERE event_key LIKE ?", "certificate-expiry:"+object.ID+":%").Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- r.queueCertificateExpiry(ctx, object.ID, now, 7, time.UTC)
		}()
	}
	wg.Wait()
	close(errors)
	for e := range errors {
		if e != nil {
			t.Fatal(e)
		}
	}
	if count() != 1 {
		t.Fatal("concurrent schedulers duplicated the certificate event")
	}
	var eventID, encrypted string
	if err = s.DB.QueryRow("SELECT id,payload_ciphertext FROM business_events WHERE event_key LIKE ?", "certificate-expiry:"+object.ID+":%").Scan(&eventID, &encrypted); err != nil {
		t.Fatal(err)
	}
	var message notifications.Message
	if err = s.Decrypt("business-event:"+eventID, encrypted, &message); err != nil || message.Event != "certificate.expiring" || message.ResourceID != object.ID {
		t.Fatal("durable reminder payload missing", err)
	}
	// Simulate the renewal finishing after the scheduler's initial scan.
	data.Fingerprint = "renewed"
	data.NotAfter = now.Add(90 * 24 * time.Hour)
	enc, _ := s.Encrypt("object:"+object.ID, data)
	if _, err = s.DB.Exec("UPDATE objects SET data_ciphertext=? WHERE id=?", enc, object.ID); err != nil {
		t.Fatal(err)
	}
	if err = r.queueCertificateExpiry(ctx, object.ID, now, 7, time.UTC); err != nil || count() != 1 {
		t.Fatal("stale scan produced an obsolete certificate notice", err)
	}
	data.NotAfter = now.Add(2 * 24 * time.Hour)
	enc, _ = s.Encrypt("object:"+object.ID, data)
	if _, err = s.DB.Exec("UPDATE objects SET data_ciphertext=? WHERE id=?", enc, object.ID); err != nil {
		t.Fatal(err)
	}
	if err = r.queueCertificateExpiry(ctx, object.ID, now, 7, time.UTC); err != nil || count() != 2 {
		t.Fatal("renewed generation cannot emit its own reminder", err)
	}
}
