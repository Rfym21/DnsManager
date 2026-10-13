package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestCloudflarePaginationAndSecretRedaction(t *testing.T) {
	pages := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages++
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("Cloudflare token auth missing")
		}
		if r.URL.Path == "/failure" {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": 10000, "message": "credential fixture-token denied"}}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{map[string]any{"id": r.URL.Query().Get("page")}}, "result_info": map[string]int{"total_pages": 2}})
	}))
	defer server.Close()
	c := cfClient{client: server.Client(), config: map[string]string{"api_url": server.URL, "api_token": "fixture-token"}}
	req := httptest.NewRequest("GET", "http://local", nil)
	items, err := c.list(req, "/items", nil)
	if err != nil || len(items) != 2 || pages != 2 {
		t.Fatalf("CF items=%v err=%v pages=%d", items, err, pages)
	}
	_, err = c.call(req, "GET", "/failure", nil)
	if err == nil || strings.Contains(err.Error(), "fixture-token") {
		t.Fatal("Cloudflare remote error leaked credentials")
	}
}

func TestCloudflareTunnelDeleteRetryAndUnownedDNSPreservation(t *testing.T) {
	deletes := 0
	mode := "missing-token"
	receipt := cfDNSReceipt{Zone: "zone", Hostname: "app.example.com", ID: "receipt-id", Token: "owned", Created: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/cfd_tunnel/tunnel"):
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": 1003, "message": "already deleted"}}})
		case r.Method == http.MethodGet:
			row := map[string]any{"id": "receipt-id", "name": receipt.Hostname, "type": "CNAME", "content": "tunnel.cfargotunnel.com", "comment": "dnsmgr:owned"}
			switch mode {
			case "missing-token":
				delete(row, "comment")
			case "changed-target":
				row["content"] = "other-tunnel.cfargotunnel.com"
			case "changed-id":
				row["id"] = "recreated-id"
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{row}})
		case r.Method == http.MethodDelete:
			deletes++
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": 1003, "message": "already deleted"}}})
		}
	}))
	defer server.Close()
	c := cfClient{client: server.Client(), config: map[string]string{"api_url": server.URL, "api_token": "fixture"}, accountID: "account"}
	req := httptest.NewRequest(http.MethodDelete, "http://local", nil)
	if _, err := cfDeleteTunnel(req, c, "tunnel"); err != nil {
		t.Fatal("successful tunnel deletion cannot resume DNS cleanup", err)
	}
	for _, value := range []string{"missing-token", "changed-target", "changed-id"} {
		mode = value
		if err := cfCleanupOwnedDNS(req, c, receipt, "tunnel"); err != nil {
			t.Fatal(err)
		}
	}
	if deletes != 0 {
		t.Fatal("Cloudflare cleanup removed an unowned or changed record")
	}
	mode = "owned"
	if err := cfCleanupOwnedDNS(req, c, receipt, "tunnel"); err != nil || deletes != 1 {
		t.Fatal("owned DNS cleanup cannot tolerate concurrent deletion", err)
	}
}

type cfVerificationFixture struct {
	dns.Provider
	pages  int
	writes int
	row    dns.Record
}

func (p *cfVerificationFixture) ListRecords(_ context.Context, options dns.ListOptions) (dns.RecordPage, error) {
	p.pages++
	if options.Page == 1 {
		return dns.RecordPage{Total: 501, Rows: make([]dns.Record, 500)}, nil
	}
	return dns.RecordPage{Total: 501, Rows: []dns.Record{p.row}}, nil
}
func (p *cfVerificationFixture) CreateRecord(_ context.Context, record dns.Record) (dns.Record, error) {
	p.writes++
	return record, nil
}
func TestCloudflareVerificationReadsAllPagesAndPreservesConflicts(t *testing.T) {
	record := dns.Record{Name: "_acme", Type: "CNAME", Value: "uuid.dcv.cloudflare.com", Line: "default", Enabled: true}
	provider := &cfVerificationFixture{row: dns.Record{Name: "_ACME.", Type: "CNAME", Value: "UUID.dcv.cloudflare.com.", Line: "default", Enabled: true}}
	req := httptest.NewRequest("POST", "http://local", nil)
	if err := cfEnsureVerification(req, provider, record); err != nil || provider.pages != 2 || provider.writes != 0 {
		t.Fatalf("CF verification duplicate check err=%v pages=%d writes=%d", err, provider.pages, provider.writes)
	}
	provider.row.Value = "manual-origin.example.com"
	if err := cfEnsureVerification(req, provider, record); err == nil || provider.writes != 0 {
		t.Fatal("CF verification overwrote a conflicting CNAME")
	}
	provider.row.Value = record.Value
	provider.row.Enabled = false
	if err := cfEnsureVerification(req, provider, record); err == nil || provider.writes != 0 {
		t.Fatal("CF disabled validation record was reported as effective")
	}
}

func TestCloudflareRoutesRejectOtherTunnelAndDeleteResumes(t *testing.T) {
	a := testAPI(t)
	_, token, csrf := testUser(t, a, "admin")
	ctx := context.Background()
	tunnelDeletes, routeDeletes, dnsDeletes := 0, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result any
		switch {
		case strings.HasSuffix(r.URL.Path, "/teamnet/routes/other-route"):
			if r.Method == http.MethodDelete {
				routeDeletes++
			}
			result = map[string]any{"id": "other-route", "tunnel_id": "other-tunnel", "network": "192.0.2.0/24"}
		case strings.HasSuffix(r.URL.Path, "/teamnet/routes"):
			result = []any{map[string]any{"id": "mine", "tunnel_id": "tunnel"}, map[string]any{"id": "other-route", "tunnel_id": "other-tunnel"}}
		case strings.HasSuffix(r.URL.Path, "/cfd_tunnel/tunnel"):
			tunnelDeletes++
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": 1003, "message": "already deleted"}}})
			return
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/dns_records"):
			result = []any{map[string]any{"id": "owned-record", "name": "app.example.com", "type": "CNAME", "content": "tunnel.cfargotunnel.com", "comment": "dnsmgr:receipt-token"}}
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/owned-record"):
			dnsDeletes++
			result = map[string]any{"id": "owned-record"}
		default:
			t.Errorf("unexpected CF API %s %s", r.Method, r.URL)
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer server.Close()
	account, err := a.Store.SaveAccount(ctx, store.Account{Name: "CF fixture", Provider: "cloudflare", Config: map[string]string{"api_url": server.URL, "api_token": "fixture", "account_id": "cf-account"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	key := "cf-tunnel:" + account.ID + ":tunnel"
	t.Cleanup(func() {
		a.Store.DB.Exec("DELETE FROM settings WHERE name=?", key)
		a.Store.DB.Exec("DELETE FROM provider_accounts WHERE id=?", account.ID)
	})
	base := "/api/v1/accounts/" + account.ID + "/cloudflare/tunnels/tunnel"
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		response := requestAPI(a, method, base+"/cidr-routes/other-route", token, csrf, nil)
		if response.Code != http.StatusNotFound || routeDeletes != 0 {
			t.Fatalf("other tunnel route reached mutation: status=%d deletes=%d", response.Code, routeDeletes)
		}
	}
	response := requestAPI(a, http.MethodGet, base+"/cidr-routes", token, csrf, nil)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "other-route") || !strings.Contains(response.Body.String(), "mine") {
		t.Fatalf("route listing exposed other tunnel: %d %s", response.Code, response.Body.String())
	}
	journal := cfTunnelJournal{Stage: "dns_pending", Pending: []cfDNSReceipt{{Zone: "zone", Hostname: "app.example.com", ID: "owned-record", Token: "receipt-token", Created: true}}}
	if err = a.Store.SaveSetting(ctx, key, journal); err != nil {
		t.Fatal(err)
	}
	response = requestAPI(a, http.MethodDelete, base, token, csrf, nil)
	if response.Code != http.StatusOK || tunnelDeletes != 1 || dnsDeletes != 1 {
		t.Fatalf("CF interrupted deletion did not clean owned DNS: %d tunnel=%d dns=%d %s", response.Code, tunnelDeletes, dnsDeletes, response.Body.String())
	}
	var saved cfTunnelJournal
	if err = a.Store.Setting(ctx, key, &saved); err != nil || saved.Stage != "complete" || len(saved.Pending) != 0 {
		t.Fatal("CF deletion cleanup checkpoint not completed", err)
	}
	response = requestAPI(a, http.MethodDelete, base, token, csrf, nil)
	if response.Code != http.StatusOK || dnsDeletes != 1 {
		t.Fatal("CF deletion retry repeated owned DNS deletion")
	}
}

func TestCloudflareIngressOwnedDNSResumeAndCleanup(t *testing.T) {
	current := map[string]any{"ingress": []any{map[string]any{"service": "http_status:404"}}, "warp-routing": map[string]any{"enabled": true}, "originRequest": map[string]any{"connectTimeout": 30}}
	records := []map[string]any{}
	created, deleted, configWrites := 0, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		var result any
		switch {
		case strings.HasSuffix(r.URL.Path, "/configurations"):
			if r.Method == "PUT" {
				configWrites++
				current = body["config"].(map[string]any)
			}
			result = map[string]any{"config": current}
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/dns_records"):
			result = records
		case r.Method == "POST":
			created++
			body["id"] = "owned-id"
			records = append(records, body)
			result = body
		case r.Method == "DELETE":
			deleted++
			records = nil
			result = map[string]any{"id": "owned-id"}
		default:
			t.Errorf("CF unexpected %s %s", r.Method, r.URL)
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer server.Close()
	c := cfClient{client: server.Client(), config: map[string]string{"api_url": server.URL, "api_token": "fixture"}, accountID: "cf-account"}
	req := httptest.NewRequest("PUT", "http://local", nil)
	domain := store.Domain{ID: "domain", AccountID: "local-account", Provider: "cloudflare", ProviderDomainID: "zone", ASCIIName: "example.com"}
	next := map[string]any{"ingress": []any{map[string]any{"hostname": "app.example.com", "service": "http://localhost:8080"}, map[string]any{"service": "http_status:404"}}}
	var saved cfTunnelJournal
	stop := true
	save := func(journal cfTunnelJournal) error {
		raw, _ := json.Marshal(journal)
		saved = cfTunnelJournal{}
		json.Unmarshal(raw, &saved)
		if stop && len(journal.Pending) > 0 && journal.Pending[0].Created {
			stop = false
			return errors.New("fixture database interrupted")
		}
		return nil
	}
	_, err := cfApplyIngress(req, c, "tunnel", next, cfHash(current), true, []store.Domain{domain}, "local-account", cfTunnelJournal{}, save)
	if err == nil || created != 1 || configWrites != 1 || saved.Stage != "dns_pending" {
		t.Fatalf("CF pause err=%v create=%d configWrites=%d stage=%s", err, created, configWrites, saved.Stage)
	}
	result, err := cfApplyIngress(req, c, "tunnel", next, "", true, []store.Domain{domain}, "local-account", saved, save)
	if err != nil || created != 1 || len(saved.Receipts) != 1 || saved.Stage != "complete" {
		t.Fatalf("CF resume err=%v creates=%d journal=%v", err, created, saved)
	}
	if result["config"].(map[string]any)["warp-routing"].(map[string]any)["enabled"] != true {
		t.Error("CF non-ingress configuration lost")
	}
	fallback := map[string]any{"ingress": []any{map[string]any{"service": "http_status:404"}}}
	_, err = cfApplyIngress(req, c, "tunnel", fallback, cfHash(current), true, []store.Domain{domain}, "local-account", saved, save)
	if err != nil || deleted != 1 || len(saved.Receipts) != 0 {
		t.Fatalf("CF owned cleanup err=%v deletes=%d receipts=%v", err, deleted, saved.Receipts)
	}
}

func TestCloudflareIngressRollbackAndUnownedRecords(t *testing.T) {
	original := map[string]any{"ingress": []any{map[string]any{"service": "http_status:404"}}, "originRequest": map[string]any{"noTLSVerify": false}}
	current := original
	configWrites, deletes := 0, 0
	failCreate := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		var result any
		switch {
		case strings.HasSuffix(r.URL.Path, "/configurations"):
			if r.Method == "PUT" {
				configWrites++
				current = body["config"].(map[string]any)
			}
			result = map[string]any{"config": current}
		case r.Method == "GET":
			result = []any{}
		case r.Method == "POST":
			if failCreate {
				json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": 1, "message": "fixture DNS denied"}}})
				return
			}
		case r.Method == "DELETE":
			deletes++
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer server.Close()
	c := cfClient{client: server.Client(), config: map[string]string{"api_url": server.URL, "api_token": "fixture"}, accountID: "cf-account"}
	req := httptest.NewRequest("PUT", "http://local", nil)
	var saved cfTunnelJournal
	save := func(journal cfTunnelJournal) error {
		raw, _ := json.Marshal(journal)
		saved = cfTunnelJournal{}
		return json.Unmarshal(raw, &saved)
	}
	domain := store.Domain{AccountID: "account", Provider: "cloudflare", ProviderDomainID: "zone", ASCIIName: "example.com"}
	next := map[string]any{"ingress": []any{map[string]any{"hostname": "app.example.com", "service": "http://localhost:8080"}, map[string]any{"service": "http_status:404"}}}
	_, err := cfApplyIngress(req, c, "tunnel", next, "", true, []store.Domain{domain}, "account", cfTunnelJournal{}, save)
	if err == nil || !strings.Contains(err.Error(), "已回滚") || cfHash(current) != cfHash(original) || configWrites != 2 || deletes != 0 {
		t.Fatalf("CF rollback err=%v writes=%d deletes=%d current=%v", err, configWrites, deletes, current)
	}
}

func TestCloudflareHostnameAndTXTValidation(t *testing.T) {
	for _, name := range []string{"https://example.com", "*.example.com", "127.0.0.1", "example.com:443", "-bad.example.com"} {
		if _, err := cfNormalizeHostname(name, false); err == nil {
			t.Errorf("CF hostname accepted %s", name)
		}
	}
	name, err := cfNormalizeHostname("_acme-challenge.Example.com.", true)
	if err != nil || name != "_acme-challenge.example.com" {
		t.Fatal(name, err)
	}
	domains := []store.Domain{{ID: "parent", ASCIIName: "example.com"}, {ID: "child", ASCIIName: "sub.example.com"}}
	matches := cfMatchingDomains(domains, "_acme-challenge.sub.example.com", "")
	if len(matches) != 1 || matches[0].ID != "child" {
		t.Fatal("CF TXT target did not choose most specific imported domain")
	}
	var host map[string]any
	json.NewDecoder(bytes.NewBufferString(`{"ownership_verification":{"name":"_cf.example.com","value":"owned"},"ssl":{"validation_records":[{"txt_name":"_acme.example.com","txt_value":"validation"}]}}`)).Decode(&host)
	if len(cfVerificationRecords(host)) != 2 {
		t.Fatal("CF TXT ownership and SSL validations not collected")
	}
	if err = cfValidateIngress(map[string]any{"ingress": []any{map[string]any{"hostname": "example.com", "service": "http://local"}}}); err == nil {
		t.Fatal("CF missing ingress fallback accepted")
	}
}
