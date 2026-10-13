package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/automation"
	"github.com/dns-manager/dnsmgr/server/internal/notifications"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestQQSignatureRejectsTamperAndReplay(t *testing.T) {
	now := time.Now()
	timestamp := fmt.Sprint(now.Unix())
	body := []byte(`{"op":0,"t":"C2C_MESSAGE_CREATE"}`)
	sig := hex.EncodeToString(ed25519.Sign(qqPrivateKey("fixture-secret"), append([]byte(timestamp), body...)))
	if !verifyQQ("fixture-secret", timestamp, sig, body, now) {
		t.Fatal("valid signature rejected")
	}
	if verifyQQ("other-secret", timestamp, sig, body, now) || verifyQQ("fixture-secret", timestamp, sig, []byte("tamper"), now) || verifyQQ("fixture-secret", timestamp, sig, body, now.Add(6*time.Minute)) {
		t.Fatal("tampered or expired signature accepted")
	}
}

func TestQQChannelBindingConsumesWindowAndRepliesFromOutbox(t *testing.T) {
	a := testAPI(t)
	u, _, _ := testUser(t, a, "admin")
	ctx := context.Background()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path == "/app/getAppAccessToken" {
			json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-token"})
			return
		}
		if r.URL.Path != "/v2/users/fixture-openid/messages" || body["msg_id"] != "fixture-message" || body["msg_seq"] != float64(1) || body["msg_type"] != float64(2) || !strings.Contains(body["markdown"].(map[string]any)["content"].(string), "绑定成功") {
			t.Errorf("binding reply contract lost: path=%s body=%v", r.URL.Path, body)
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "reply-sent"})
	}))
	defer server.Close()
	channel := notifications.Channel{Provider: "qq", Config: map[string]string{"app_id": "fixture-app", "app_secret": "fixture-secret", "api_base": server.URL}}
	raw, _ := json.Marshal(channel)
	object, err := a.Store.SaveObject(ctx, store.Object{Kind: "notification_channels", OwnerID: u.ID, Name: "QQ callback fixture", Active: true, Data: raw}, true)
	if err != nil {
		t.Fatal(err)
	}
	key := "qq_binding:" + object.ID
	t.Cleanup(func() {
		a.Store.DB.Exec("DELETE FROM notification_outbox WHERE channel_id=?", object.ID)
		a.Store.DB.Exec("DELETE FROM settings WHERE name=? OR name LIKE 'qqcallback:%'", key)
		a.Store.DB.Exec("DELETE FROM objects WHERE id=?", object.ID)
	})
	if err = a.Store.SaveSetting(ctx, key, map[string]any{"until": time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	body := `{"op":0,"t":"C2C_MESSAGE_CREATE","id":"fixture-event","d":{"id":"fixture-message","author":{"user_openid":"fixture-openid"}}}`
	stamp := fmt.Sprint(time.Now().Unix())
	signature := hex.EncodeToString(ed25519.Sign(qqPrivateKey("fixture-secret"), []byte(stamp+body)))
	request := func(content, sig string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/webhooks/qq/"+object.ID, strings.NewReader(content))
		r.Header.Set("X-Bot-Appid", "fixture-app")
		r.Header.Set("X-Signature-Timestamp", stamp)
		r.Header.Set("X-Signature-Ed25519", sig)
		w := httptest.NewRecorder()
		a.Router.ServeHTTP(w, r)
		return w
	}
	if response := request(body, "bad"); response.Code != http.StatusUnauthorized {
		t.Fatal("unsigned callback accepted")
	}
	for n := 0; n < 2; n++ {
		if response := request(body, signature); response.Code != http.StatusOK {
			t.Fatalf("QQ callback failed: %d %s", response.Code, response.Body.String())
		}
	}
	if requests != 0 {
		t.Fatal("callback sent an external notification before outbox delivery")
	}
	var count int
	a.Store.DB.QueryRow("SELECT COUNT(*) FROM notification_outbox WHERE channel_id=?", object.ID).Scan(&count)
	if count != 1 {
		t.Fatal("binding reply is not durably deduplicated", count)
	}
	other := strings.ReplaceAll(body, "fixture-openid", "other-openid")
	other = strings.ReplaceAll(other, "fixture-event", "other-event")
	otherSig := hex.EncodeToString(ed25519.Sign(qqPrivateKey("fixture-secret"), []byte(stamp+other)))
	if response := request(other, otherSig); response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	updated, _ := a.Store.Object(ctx, object.ID)
	json.Unmarshal(updated.Data, &channel)
	if channel.Config["openid"] != "fixture-openid" {
		t.Fatal("later bot message replaced the recipient after binding window consumed")
	}
	// An eventual recipient edit must not redirect the queued binding reply.
	channel.Config["openid"] = "edited-openid"
	enc, _ := a.Store.Encrypt("object:"+object.ID, channel)
	a.Store.DB.Exec("UPDATE objects SET data_ciphertext=? WHERE id=?", enc, object.ID)
	if err = (&automation.Runner{Store: a.Store}).DeliverNotifications(ctx); err != nil || requests != 2 {
		t.Fatal("durable binding reply was not sent through Sender", err, requests)
	}
	var state string
	a.Store.DB.QueryRow("SELECT state FROM notification_outbox WHERE channel_id=?", object.ID).Scan(&state)
	if state != "sent" {
		t.Fatal("outbox did not confirm binding reply", state)
	}
}
