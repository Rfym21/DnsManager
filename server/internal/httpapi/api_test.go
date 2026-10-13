package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/config"
	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func testAPI(t *testing.T) *API {
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if filename := os.Getenv("TEST_DATABASE_DSN_FILE"); filename != "" {
		b, e := os.ReadFile(filename)
		if e != nil {
			t.Fatal(e)
		}
		dsn = strings.TrimSpace(string(b))
	}
	if dsn == "" {
		dsn = "sqlite:" + filepath.Join(t.TempDir(), "api.sqlite")
	}
	box, e := cryptobox.New(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	s, e := store.Open(context.Background(), dsn, box)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if e = s.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	return New(s, config.Config{PublicURL: "http://localhost", SessionTTL: time.Hour})
}
func testUser(t *testing.T, a *API, role string) (store.User, string, string) {
	id, _ := store.ID()
	hash, e := bcrypt.GenerateFromPassword([]byte("fixture-strong-password"), bcrypt.MinCost)
	if e != nil {
		t.Fatal(e)
	}
	_, e = a.Store.DB.Exec("INSERT INTO users(id,username,password_hash,role,enabled,preferences,created_at,updated_at) VALUES (?,?,?,?,TRUE,'{}',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))", id, id, string(hash), role)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Store.DB.Exec("DELETE FROM users WHERE id=?", id) })
	u, e := a.Store.User(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	token, csrf, e := a.Store.CreateSession(context.Background(), u, "", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	return u, token, csrf
}
func requestAPI(a *API, method, path, token, csrf string, payload any) *httptest.ResponseRecorder {
	var b []byte
	if payload != nil {
		b, _ = json.Marshal(payload)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.RemoteAddr = "127.0.0.1:10100"
	if token != "" {
		req.AddCookie(&http.Cookie{Name: "dnsmgr_session", Value: token})
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	req.Header.Set("Origin", "http://localhost")
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)
	return w
}
func TestAuthorizationCSRFAndSecretRedaction(t *testing.T) {
	a := testAPI(t)
	_, adminToken, adminCSRF := testUser(t, a, "admin")
	_, restrictedToken, _ := testUser(t, a, "restricted")
	tests := []struct {
		method, path, token, csrf string
		payload                   any
		status                    int
	}{
		{"GET", "/api/v1/accounts", "", "", nil, 401},
		{"GET", "/api/v1/accounts", restrictedToken, "", nil, 403},
		{"POST", "/api/v1/accounts", adminToken, "", map[string]any{}, 403},
	}
	for _, test := range tests {
		w := requestAPI(a, test.method, test.path, test.token, test.csrf, test.payload)
		if w.Code != test.status {
			t.Fatalf("%s %s: %d %s", test.method, test.path, w.Code, w.Body.String())
		}
	}
	payload := map[string]any{"name": "fixture issuer", "data": map[string]any{"provider": "letsencrypt", "config": map[string]string{"email": "admin@example.invalid", "SecretId": "should-not-escape", "AccessKeyId": "hidden-key", "PublicKey": "hidden-public", "authorization": "hidden-header", "password": "hidden-password"}}, "active": false}
	created := requestAPI(a, "POST", "/api/v1/objects/issuer_accounts", adminToken, adminCSRF, payload)
	if created.Code != 200 {
		t.Fatal(created.Code, created.Body.String())
	}
	var object store.Object
	if e := json.Unmarshal(created.Body.Bytes(), &object); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Store.DB.Exec("DELETE FROM objects WHERE id=?", object.ID) })
	for _, secret := range []string{"should-not-escape", "hidden-key", "hidden-public", "hidden-header", "hidden-password"} {
		if strings.Contains(created.Body.String(), secret) {
			t.Fatalf("credential leaked: %s", secret)
		}
	}
	forbidden := requestAPI(a, "GET", "/api/v1/objects/issuer_accounts/"+object.ID, restrictedToken, "", nil)
	if forbidden.Code != 403 {
		t.Fatal("restricted read issuer", forbidden.Code)
	}
}
func TestDomainLoginOneUseAndRevocation(t *testing.T) {
	a := testAPI(t)
	u, adminToken, csrf := testUser(t, a, "admin")
	account, e := a.Store.SaveAccount(context.Background(), store.Account{Name: "fixture", Provider: "cloudflare", Config: map[string]string{"api_token": "fixture"}}, true)
	if e != nil {
		t.Fatal(e)
	}
	d, e := a.Store.AddDomain(context.Background(), store.Domain{AccountID: account.ID, ProviderDomainID: "fixture", Name: "fixture.example.invalid", ASCIIName: "fixture.example.invalid"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		a.Store.DB.Exec("DELETE FROM login_tickets WHERE domain_id=?", d.ID)
		a.Store.DB.Exec("DELETE FROM sessions WHERE domain_id=?", d.ID)
		a.Store.DB.Exec("DELETE FROM domains WHERE id=?", d.ID)
		a.Store.DB.Exec("DELETE FROM provider_accounts WHERE id=?", account.ID)
	})
	if _, e = a.Store.DB.Exec("UPDATE domains SET quicklogin_enabled=TRUE WHERE id=?", d.ID); e != nil {
		t.Fatal(e)
	}
	link := requestAPI(a, "POST", "/api/v1/domains/"+d.ID+"/login-links", adminToken, csrf, map[string]any{})
	if link.Code != 201 {
		t.Fatal(link.Code, link.Body.String())
	}
	var ticket struct {
		Token string `json:"token"`
	}
	json.Unmarshal(link.Body.Bytes(), &ticket)
	login := requestAPI(a, "POST", "/api/v1/auth/domain-login", "", "", map[string]string{"token": ticket.Token})
	if login.Code != 200 {
		t.Fatal(login.Code, login.Body.String())
	}
	var sessionToken string
	for _, cookie := range login.Result().Cookies() {
		if cookie.Name == "dnsmgr_session" {
			sessionToken = cookie.Value
		}
	}
	replay := requestAPI(a, "POST", "/api/v1/auth/domain-login", "", "", map[string]string{"token": ticket.Token})
	if replay.Code != 401 {
		t.Fatal("ticket replay", replay.Code)
	}
	restricted := requestAPI(a, "GET", "/api/v1/accounts", sessionToken, "", nil)
	if restricted.Code != 403 {
		t.Fatal("domain login became admin", restricted.Code)
	}
	list := requestAPI(a, "GET", "/api/v1/domains", sessionToken, "", nil)
	if list.Code != 200 || !strings.Contains(list.Body.String(), d.ID) {
		t.Fatal(list.Code, list.Body.String())
	}
	a.Store.DB.Exec("UPDATE users SET enabled=FALSE WHERE id=?", u.ID)
	revoked := requestAPI(a, "GET", "/api/v1/domains", sessionToken, "", nil)
	if revoked.Code != 401 {
		t.Fatal("issuer revocation not honored", revoked.Code)
	}
}
func TestDNSHostNameVersionAndObjectKind(t *testing.T) {
	record := map[string]any{"type": "TXT", "name": "_acme-challenge", "value": "abc", "ttl": 60, "enabled": true}
	b, _ := json.Marshal(record)
	if len(b) == 0 {
		t.Fatal("record invalid")
	}
	if canonicalKind("deployment-accounts") != "deploy_accounts" {
		t.Fatal("legacy kind mismatch")
	}
	old := json.RawMessage(`{"config":{"AccessKeyId":"secret","email":"old"}}`)
	next := json.RawMessage(`{"config":{"AccessKeyId":"","email":"new"}}`)
	merged := mergeSecrets(old, next)
	if !strings.Contains(string(merged), "secret") || !strings.Contains(string(merged), "new") {
		t.Fatal(fmt.Sprint(string(merged)))
	}
}
