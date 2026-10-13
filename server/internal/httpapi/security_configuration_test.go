package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestWebhookSecretsSurviveEditWithoutExposure(t *testing.T) {
	a := testAPI(t)
	_, token, csrf := testUser(t, a, "admin")
	payload := map[string]any{"name": "fixture webhook", "active": true, "data": map[string]any{"provider": "custom_webhook", "config": map[string]string{"url": "https://example.invalid/hook/fixture-secret", "headers": "Authorization: Bearer header-secret", "method": "POST"}}}
	created := requestAPI(a, "POST", "/api/v1/objects/notification_channels", token, csrf, payload)
	if created.Code != 200 {
		t.Fatal(created.Code, created.Body.String())
	}
	var o store.Object
	json.Unmarshal(created.Body.Bytes(), &o)
	t.Cleanup(func() { a.Store.DB.Exec("DELETE FROM objects WHERE id=?", o.ID) })
	if strings.Contains(created.Body.String(), "fixture-secret") || strings.Contains(created.Body.String(), "header-secret") {
		t.Fatal("webhook credentials escaped")
	}
	patch := map[string]any{"name": "edited webhook", "active": true, "version": o.Version, "data": map[string]any{"provider": "custom_webhook", "config": map[string]string{"url": "", "headers": "", "method": "PUT"}}}
	w := requestAPI(a, "PATCH", "/api/v1/objects/notification_channels/"+o.ID, token, csrf, patch)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	saved, err := a.Store.Object(context.Background(), o.ID)
	if err != nil || !strings.Contains(string(saved.Data), "fixture-secret") || !strings.Contains(string(saved.Data), "header-secret") || !strings.Contains(string(saved.Data), "PUT") {
		t.Fatal("blank secrets were overwritten", err)
	}
}

func TestInternalSettingsNeverReadOrPartiallyWritten(t *testing.T) {
	a := testAPI(t)
	_, token, csrf := testUser(t, a, "admin")
	if _, err := a.Store.DB.Exec("INSERT INTO settings(name,ciphertext,updated_at) VALUES('qqcallback:invalid-fixture','invalid-cipher',UTC_TIMESTAMP(6))"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Store.DB.Exec("DELETE FROM settings WHERE name='qqcallback:invalid-fixture'") })
	w := requestAPI(a, "GET", "/api/v1/settings", token, "", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "qqcallback") {
		t.Fatal("internal setting processed", w.Code)
	}
	w = requestAPI(a, "PUT", "/api/v1/settings", token, csrf, map[string]any{"items": map[string]any{"site": map[string]string{"name": "not-committed"}, "qq_binding:forged": map[string]string{"until": "2099"}}})
	if w.Code != 403 {
		t.Fatal("forged internal setting accepted", w.Code)
	}
	var site map[string]any
	a.Store.Setting(context.Background(), "site", &site)
	if site["name"] == "not-committed" {
		t.Fatal("partial settings committed")
	}
}
