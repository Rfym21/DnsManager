package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dns-manager/dnsmgr/server/internal/domaininfo"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestLoginLogoutAuditAndSessionRevocation(t *testing.T) {
	a := testAPI(t)
	u, _, _ := testUser(t, a, "restricted")
	w := requestAPI(a, "POST", "/api/v1/auth/login", "", "", map[string]string{"username": u.Username, "password": "fixture-strong-password"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var response struct {
		CSRF string `json:"csrf_token"`
	}
	json.Unmarshal(w.Body.Bytes(), &response)
	var token string
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "dnsmgr_session" {
			token = cookie.Value
		}
	}
	if token == "" {
		t.Fatal("session cookie missing")
	}
	w = requestAPI(a, "POST", "/api/v1/auth/logout", token, response.CSRF, nil)
	if w.Code != 200 || requestAPI(a, "GET", "/api/v1/auth/me", token, "", nil).Code != 401 {
		t.Fatal("logout did not revoke session", w.Code)
	}
	for _, action := range []string{"auth.login", "auth.logout"} {
		var count int
		if e := a.Store.DB.QueryRow("SELECT COUNT(*) FROM audit_events WHERE actor_id=? AND action=?", u.ID, action).Scan(&count); e != nil || count != 1 {
			t.Fatal("missing audit", action, count, e)
		}
	}
}

func TestDomainDateRefreshPreservesKnownRegistrationAndPartialEditValidation(t *testing.T) {
	a := testAPI(t)
	u, token, csrf := testUser(t, a, "admin")
	ctx := context.Background()
	account, err := a.Store.SaveAccount(ctx, store.Account{Name: "registry fixture", Provider: "cloudflare", Config: map[string]string{"api_token": "fixture"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	d, err := a.Store.AddDomain(ctx, store.Domain{AccountID: account.ID, ProviderDomainID: "registry", Name: "example.com", ASCIIName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.Store.DB.Exec("DELETE FROM domains WHERE id=?", d.ID)
		a.Store.DB.Exec("DELETE FROM provider_accounts WHERE id=?", account.ID)
	})
	path := "/api/v1/domains/" + d.ID + "/dates"
	w := requestAPI(a, "PUT", path, token, csrf, map[string]string{"registered_at": "2020-01-01", "expires_at": "2030-01-01"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = requestAPI(a, "PUT", path, token, csrf, map[string]string{"expires_at": "2019-01-01"})
	if w.Code != 400 {
		t.Fatal("partial edit bypassed date order", w.Code)
	}
	var remote *httptest.Server
	remote = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bootstrap" {
			json.NewEncoder(w).Encode(map[string]any{"services": [][][]string{{{"com"}, {remote.URL}}}})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"events": []map[string]string{{"eventAction": "expiration", "eventDate": "2032-01-01T00:00:00Z"}}})
		}
	}))
	defer remote.Close()
	registryLookup = domaininfo.Lookup{BootstrapURL: remote.URL + "/bootstrap"}
	t.Cleanup(func() { registryLookup = domaininfo.Lookup{} })
	w = requestAPI(a, "POST", path+"/refresh", token, csrf, map[string]any{})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = requestAPI(a, "GET", path, token, "", nil)
	var dates map[string]any
	json.Unmarshal(w.Body.Bytes(), &dates)
	if dates["registered_at"] != "2020-01-01T00:00:00Z" || dates["expires_at"] != "2032-01-01T00:00:00Z" {
		t.Fatal(dates)
	}
	if e := a.Store.Audit(ctx, u.ID, "record.update", "record", "r", d.ID, "request", map[string]bool{"ok": true}); e != nil {
		t.Fatal(e)
	}
	w = requestAPI(a, "GET", "/api/v1/audit?domain_id="+d.ID, token, "", nil)
	var audit struct {
		Items []struct {
			Domain string `json:"domain_id"`
		}
	}
	json.Unmarshal(w.Body.Bytes(), &audit)
	if w.Code != 200 || len(audit.Items) == 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, event := range audit.Items {
		if event.Domain != d.ID {
			t.Fatal("unfiltered audit", event)
		}
	}
}

func TestProxySettingMatchesTransportValidation(t *testing.T) {
	for _, value := range []string{"http://localhost", "http://localhost:0", "http://localhost:65536", "http://localhost:8080/path", "socks5://localhost:1080?x=1"} {
		raw, _ := json.Marshal(map[string]string{"proxy_url": value})
		if validateSetting("network", raw) == nil {
			t.Fatal("accepted invalid proxy", value)
		}
	}
	for _, value := range []string{"http://localhost:8080", "socks5h://user:password@localhost:1080", "https://[::1]:443"} {
		raw, _ := json.Marshal(map[string]string{"proxy_url": value})
		if err := validateSetting("network", raw); err != nil {
			t.Fatal(value, err)
		}
	}
}
