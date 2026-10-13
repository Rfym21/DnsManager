package httpapi

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/automation"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

type legacyDNSFixture struct {
	dns.Provider
	clientPage bool
	fail       bool
	writes     int
}

func (p *legacyDNSFixture) Descriptor() dns.Descriptor {
	return dns.Descriptor{ID: "fixture", Name: "fixture", Capabilities: dns.Capabilities{Status: true, Remark: 1, Groups: true, ClientPagination: p.clientPage}}
}
func (p *legacyDNSFixture) Lines(context.Context) ([]dns.Line, error) {
	return []dns.Line{{ID: "default", Name: "默认", Parent: ""}}, nil
}
func (p *legacyDNSFixture) MinTTL(context.Context) (int, error) { return 60, nil }
func (p *legacyDNSFixture) ListRecords(context.Context, dns.ListOptions) (dns.RecordPage, error) {
	if p.fail {
		return dns.RecordPage{}, errors.New("fixture rejection")
	}
	return dns.RecordPage{Total: 1, Rows: []dns.Record{{ID: "r1", Name: "www", Type: "A", Value: "192.0.2.1", TTL: 600, Line: "default", Enabled: true}}}, nil
}
func (p *legacyDNSFixture) mutate() error {
	p.writes++
	if p.fail {
		return errors.New("fixture rejection")
	}
	return nil
}
func (p *legacyDNSFixture) CreateRecord(_ context.Context, r dns.Record) (dns.Record, error) {
	return r, p.mutate()
}
func (p *legacyDNSFixture) UpdateRecord(_ context.Context, _ string, r dns.Record) (dns.Record, error) {
	return r, p.mutate()
}
func (p *legacyDNSFixture) DeleteRecord(context.Context, string) error       { return p.mutate() }
func (p *legacyDNSFixture) SetStatus(context.Context, string, bool) error    { return p.mutate() }
func (p *legacyDNSFixture) SetRemark(context.Context, string, string) error  { return p.mutate() }
func (p *legacyDNSFixture) Groups(context.Context) ([]dns.Group, error)      { return nil, nil }
func (p *legacyDNSFixture) SetGroup(context.Context, []string, string) error { return p.mutate() }

type legacyFixture struct {
	a                 *API
	provider          *legacyDNSFixture
	admin, restricted store.User
	domain            store.Domain
	certID            string
}

func newLegacyFixture(t *testing.T) legacyFixture {
	a := testAPI(t)
	ctx := context.Background()
	admin, _, _ := testUser(t, a, "admin")
	restricted, _, _ := testUser(t, a, "restricted")
	id, _ := store.ID()
	source := "fixture-" + id
	for key, value := range map[string]string{"migration.source_id": source, "legacy.sys_key": "fixture-system-key"} {
		var old string
		err := a.Store.DB.QueryRow("SELECT ciphertext FROM settings WHERE name=?", key).Scan(&old)
		if e := a.Store.SaveSetting(ctx, key, value); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if err == nil {
				a.Store.DB.Exec("UPDATE settings SET ciphertext=? WHERE name=?", old, key)
			} else {
				a.Store.DB.Exec("DELETE FROM settings WHERE name=?", key)
			}
		})
	}
	for old, u := range map[string]store.User{"1": admin, "2": restricted} {
		enc, err := a.Store.Box.Seal("legacy-api:"+u.ID, []byte("fixture-api-key"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = a.Store.DB.Exec("INSERT INTO legacy_identities(source_id,legacy_id,user_id,api_enabled,api_key_ciphertext) VALUES(?,?,?,TRUE,?)", source, old, u.ID, enc); err != nil {
			t.Fatal(err)
		}
	}
	account, err := a.Store.SaveAccount(ctx, store.Account{Name: "legacy-fixture", Provider: "cloudflare", Config: map[string]string{"auth": "1", "apikey": "invalid-fixture"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	d, err := a.Store.AddDomain(ctx, store.Domain{AccountID: account.ID, Name: "legacy.example.invalid", ASCIIName: "legacy.example.invalid", ProviderDomainID: "fixture-zone"})
	if err != nil {
		t.Fatal(err)
	}
	a.Store.DB.Exec("UPDATE domains SET quicklogin_enabled=TRUE WHERE id=?", d.ID)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: d.Name}, DNSNames: []string{d.Name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	raw, _ := json.Marshal(automation.CertificateData{Domains: []string{d.Name}, Fullchain: chain, PrivateKey: private, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Status: "issued"})
	cert, err := a.Store.SaveObject(ctx, store.Object{Kind: "certificates", Name: "fixture", OwnerID: admin.ID, Data: raw}, true)
	if err != nil {
		t.Fatal(err)
	}
	for table, mapping := range map[string][2]string{"account": {"11", account.ID}, "domain": {"21", d.ID}, "cert_order": {"31", cert.ID}} {
		if _, err = a.Store.DB.Exec("INSERT INTO legacy_resources(source_id,source_table,source_id_value,target_id) VALUES(?,?,?,?)", source, table, mapping[0], mapping[1]); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		a.Store.DB.Exec("DELETE FROM login_tickets WHERE domain_id=?", d.ID)
		a.Store.DB.Exec("DELETE FROM sessions WHERE domain_id=?", d.ID)
		a.Store.DB.Exec("DELETE FROM domain_grants WHERE domain_id=?", d.ID)
		a.Store.DB.Exec("DELETE FROM domains WHERE id=?", d.ID)
		a.Store.DB.Exec("DELETE FROM provider_accounts WHERE id=?", account.ID)
		a.Store.DB.Exec("DELETE FROM objects WHERE id=?", cert.ID)
		a.Store.DB.Exec("DELETE FROM legacy_resources WHERE source_id=?", source)
	})
	provider := &legacyDNSFixture{}
	a.DNSFactory = func(string, map[string]string, string, string) (dns.Provider, error) { return provider, nil }
	return legacyFixture{a: a, provider: provider, admin: admin, restricted: restricted, domain: d, certID: cert.ID}
}
func legacyRequest(a *API, path, uid string, values url.Values) *httptest.ResponseRecorder {
	if values == nil {
		values = url.Values{}
	}
	values.Set("uid", uid)
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	values.Set("timestamp", stamp)
	digest := md5.Sum([]byte(uid + stamp + "fixture-api-key"))
	values.Set("sign", hex.EncodeToString(digest[:]))
	r := httptest.NewRequest("POST", path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, r)
	return w
}

func TestLegacyTenRoutesAndPermissionContract(t *testing.T) {
	f := newLegacyFixture(t)
	forms := url.Values{"name": {"www"}, "type": {"A"}, "value": {"192.0.2.2"}, "recordid": {"r1"}, "status": {"1"}, "remark": {"fixture"}, "action": {"open"}, "recordinfo": {`[{"RecordId":"r1"}]`}, "id": {"31"}}
	routes := []string{"/api/domain", "/api/domain/21", "/api/record/data/21", "/api/record/add/21", "/api/record/update/21", "/api/record/delete/21", "/api/record/status/21", "/api/record/remark/21", "/api/record/batch/21", "/api/cert/order"}
	for _, path := range routes {
		values := url.Values{}
		for k, v := range forms {
			values[k] = append([]string(nil), v...)
		}
		if path == "/api/domain" {
			values.Del("id")
		}
		w := legacyRequest(f.a, path, "1", values)
		if w.Code != 200 || strings.Contains(w.Body.String(), `"code":-1`) {
			t.Fatalf("admin %s: %d %s", path, w.Code, w.Body.String())
		}
		if path == "/api/cert/order" && !strings.Contains(w.Body.String(), `"pfx"`) {
			t.Fatal("legacy cert PFX missing")
		}
		before := f.provider.writes
		w = legacyRequest(f.a, path, "2", values)
		if path == "/api/domain" {
			if !strings.Contains(w.Body.String(), `"total":0`) {
				t.Fatal(w.Body.String())
			}
		} else if !strings.Contains(w.Body.String(), `"code":-1`) {
			t.Fatalf("restricted %s: %s", path, w.Body.String())
		}
		if f.provider.writes != before {
			t.Fatalf("forbidden route wrote: %s", path)
		}
	}
	if _, err := f.a.Store.DB.Exec("INSERT INTO domain_grants(user_id,domain_id,permissions) VALUES(?,?,'[\"dns:read\",\"dns:write\"]')", f.restricted.ID, f.domain.ID); err != nil {
		t.Fatal(err)
	}
	w := legacyRequest(f.a, "/api/record/add/21", "2", forms)
	if !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatal("granted restricted write", w.Body.String())
	}
	f.provider.clientPage = true
	w = legacyRequest(f.a, "/api/record/data/21", "1", nil)
	if !strings.HasPrefix(w.Body.String(), "[") {
		t.Fatal("bare array compatibility lost", w.Body.String())
	}
	f.provider.clientPage = false
	w = legacyRequest(f.a, "/api/record/data/21", "1", nil)
	if !strings.Contains(w.Body.String(), `"total":1`) || !strings.Contains(w.Body.String(), `"RecordId":"r1"`) {
		t.Fatal(w.Body.String())
	}
	f.provider.fail = true
	for _, path := range routes[2:9] {
		w = legacyRequest(f.a, path, "1", forms)
		if path == "/api/record/data/21" {
			if !strings.Contains(w.Body.String(), `"total":0`) {
				t.Fatal(w.Body.String())
			}
		} else if path == "/api/record/batch/21" {
			if !strings.Contains(w.Body.String(), "成功启用0条") {
				t.Fatal(w.Body.String())
			}
		} else if !strings.Contains(w.Body.String(), `"code":-1`) {
			t.Fatalf("provider error hidden %s %s", path, w.Body.String())
		}
	}
}

func TestLegacySignatureAndQuickloginReplay(t *testing.T) {
	f := newLegacyFixture(t)
	for _, values := range []url.Values{{}, {"uid": {"1"}, "timestamp": {"1"}, "sign": {"bad"}}, {"uid": {"1"}, "timestamp": {strconv.FormatInt(time.Now().Unix(), 10)}, "sign": {"UPPERCASE"}}} {
		r := httptest.NewRequest("POST", "/api/domain", strings.NewReader(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		f.a.Router.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := legacyRequest(f.a, "/api/domain/21", "1", url.Values{"loginurl": {"1"}})
	var data struct {
		Data map[string]any `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &data)
	link, ok := data.Data["loginurl"].(string)
	if !ok {
		t.Fatal(w.Body.String())
	}
	request := httptest.NewRequest("GET", link, nil)
	first := httptest.NewRecorder()
	f.a.Router.ServeHTTP(first, request)
	if first.Code != 303 || len(first.Result().Cookies()) == 0 {
		t.Fatal(first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	f.a.Router.ServeHTTP(second, httptest.NewRequest("GET", link, nil))
	if second.Code != 401 {
		t.Fatal("quicklogin replay", second.Code)
	}
	request = httptest.NewRequest("GET", "/api/v1/accounts", nil)
	request.AddCookie(first.Result().Cookies()[0])
	protected := httptest.NewRecorder()
	f.a.Router.ServeHTTP(protected, request)
	if protected.Code != 403 {
		t.Fatal("legacy domain session became admin", protected.Code)
	}
	if _, err := f.a.Store.DB.Exec("UPDATE users SET enabled=FALSE WHERE id=?", f.admin.ID); err != nil {
		t.Fatal(err)
	}
	w = legacyRequest(f.a, "/api/domain", "1", nil)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "被封禁") {
		t.Fatal("legacy disable not honored", w.Code, w.Body.String())
	}
}
