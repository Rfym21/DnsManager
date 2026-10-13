package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCaptchaExpiryTamperingReplayAndProtectedSettings(t *testing.T) {
	a := testAPI(t)
	_, token, csrf := testUser(t, a, "admin")
	result := requestAPI(a, "GET", "/api/v1/auth/captcha", "", "", nil)
	if result.Code != 200 {
		t.Fatal(result.Code, result.Body.String())
	}
	var response struct {
		Token string `json:"token"`
		Image string `json:"image"`
	}
	json.Unmarshal(result.Body.Bytes(), &response)
	raw, e := a.Store.Box.Open("login-captcha", response.Token)
	if e != nil {
		t.Fatal(e)
	}
	var challenge captchaToken
	json.Unmarshal(raw, &challenge)
	if response.Image == "" || challenge.Answer == "" {
		t.Fatal("missing challenge")
	}
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.RemoteAddr = "127.0.0.1:10100"
	if a.consumeCaptcha(req, response.Token+"x", challenge.Answer) || a.consumeCaptcha(req, response.Token, "xxxxx") {
		t.Fatal("accepted forged challenge")
	}
	challenge.Until = time.Now().Add(-time.Minute)
	expired, _ := json.Marshal(challenge)
	expiredToken, _ := a.Store.Box.Seal("login-captcha", expired)
	if a.consumeCaptcha(req, expiredToken, challenge.Answer) {
		t.Fatal("expired captcha accepted")
	}
	if !a.consumeCaptcha(req, response.Token, challenge.Answer) || a.consumeCaptcha(req, response.Token, challenge.Answer) {
		t.Fatal("single use requirement failed")
	}
	for _, name := range []string{"qq_binding:channel", "cf-tunnel:receipt", "captcha_used:nonce", "system.runtime"} {
		result = requestAPI(a, "PUT", "/api/v1/settings", token, csrf, map[string]any{"items": map[string]any{name: map[string]any{"ready": true}}})
		if result.Code != 403 {
			t.Fatalf("%s: %d %s", name, result.Code, result.Body.String())
		}
	}
}
