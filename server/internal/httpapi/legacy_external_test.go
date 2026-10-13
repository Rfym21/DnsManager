package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/notifications"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestQQCallbackChallengeSignatureAndDeduplication(t *testing.T) {
	f := newLegacyFixture(t)
	a := f.a
	ctx := context.Background()
	for key, value := range map[string]string{"legacy.qqbot_appid": "fixture-app", "legacy.qqbot_appsecret": "fixture-secret"} {
		if err := a.Store.SaveSetting(ctx, key, value); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.Store.DB.Exec("DELETE FROM settings WHERE name=?", key) })
	}
	t.Cleanup(func() {
		a.Store.DB.Exec("DELETE FROM settings WHERE name='legacy.qqbot_openid' OR name LIKE 'qqcallback:%'")
	})
	channel := notifications.Channel{Provider: "qq", Config: map[string]string{"app_id": "fixture-app", "app_secret": "fixture-secret"}}
	raw, _ := json.Marshal(channel)
	object, err := a.Store.SaveObject(ctx, store.Object{Kind: "notification_channels", Name: "legacy QQ fixture", OwnerID: f.admin.ID, Active: true, Data: raw}, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Store.DB.Exec("INSERT INTO legacy_resources(source_id,source_table,source_id_value,target_id) VALUES('qqfixture','config','notification:qqbot',?)", object.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.Store.DB.Exec("DELETE FROM legacy_resources WHERE target_id=?", object.ID)
		a.Store.DB.Exec("DELETE FROM notification_outbox WHERE channel_id=?", object.ID)
		a.Store.DB.Exec("DELETE FROM objects WHERE id=?", object.ID)
	})
	challenge := `{"op":13,"d":{"event_ts":"123","plain_token":"fixture-token"}}`
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, httptest.NewRequest("POST", "/qqbot/webhook", strings.NewReader(challenge)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	sig, _ := hex.DecodeString(result["signature"])
	private := qqPrivateKey("fixture-secret")
	if !ed25519.Verify(private.Public().(ed25519.PublicKey), []byte("123fixture-token"), sig) {
		t.Fatal("challenge signature invalid")
	}
	body := `{"op":0,"t":"C2C_MESSAGE_CREATE","id":"fixture-event","d":{"id":"fixture-message","author":{"user_openid":"fixture-openid"}}}`
	stamp := fmt.Sprint(time.Now().Unix())
	request := func(signature string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/qqbot/webhook", strings.NewReader(body))
		r.Header.Set("X-Bot-Appid", "fixture-app")
		r.Header.Set("X-Signature-Timestamp", stamp)
		r.Header.Set("X-Signature-Ed25519", signature)
		w := httptest.NewRecorder()
		a.Router.ServeHTTP(w, r)
		return w
	}
	if w = request("bad"); w.Code != 401 {
		t.Fatal("invalid signature accepted", w.Code)
	}
	signed := hex.EncodeToString(ed25519.Sign(private, []byte(stamp+body)))
	for n := 0; n < 2; n++ {
		if w = request(signed); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	var openid string
	if err := a.Store.Setting(ctx, "legacy.qqbot_openid", &openid); err != nil || openid != "fixture-openid" {
		t.Fatal("binding not saved", err)
	}
	var count int
	a.Store.DB.QueryRow("SELECT COUNT(*) FROM settings WHERE name LIKE 'qqcallback:%'").Scan(&count)
	if count != 2 {
		t.Fatal("callback not deduplicated", count)
	}
	updated, _ := a.Store.Object(ctx, object.ID)
	json.Unmarshal(updated.Data, &channel)
	if channel.Config["openid"] != "fixture-openid" {
		t.Fatal("legacy callback did not update migrated QQ recipient")
	}
	a.Store.DB.QueryRow("SELECT COUNT(*) FROM notification_outbox WHERE channel_id=?", object.ID).Scan(&count)
	if count != 1 {
		t.Fatal("legacy binding reply not durably queued", count)
	}
}

func TestLegacyBusinessStatusAndCronAuthentication(t *testing.T) {
	f := newLegacyFixture(t)
	a := f.a
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, httptest.NewRequest("GET", "/dmtask/status", nil))
	if w.Body.String() != "error" {
		t.Fatal(w.Body.String())
	}
	if _, err := a.Store.DB.Exec("INSERT INTO worker_heartbeats(worker_id,last_seen,capabilities) VALUES('legacy-fixture',UTC_TIMESTAMP(6),'[]')"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Store.DB.Exec("DELETE FROM worker_heartbeats WHERE worker_id='legacy-fixture'") })
	w = httptest.NewRecorder()
	a.Router.ServeHTTP(w, httptest.NewRequest("GET", "/dmtask/status", nil))
	if w.Body.String() != "ok" {
		t.Fatal(w.Body.String())
	}
	for key, value := range map[string]string{"legacy.cron_type": "1", "legacy.cron_key": "fixture-cron-key"} {
		a.Store.SaveSetting(context.Background(), key, value)
		t.Cleanup(func() { a.Store.DB.Exec("DELETE FROM settings WHERE name=?", key) })
	}
	w = httptest.NewRecorder()
	a.Router.ServeHTTP(w, httptest.NewRequest("GET", "/cron?key=incorrect", nil))
	if w.Body.String() != "访问密钥错误" {
		t.Fatal(w.Body.String())
	}
	// Running cron would schedule configured tasks; auth rejection must leave
	// that path unexecuted. Clock bounds are covered by the signed API fixtures.
	_ = time.Now()
}
