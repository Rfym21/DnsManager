package cert

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func certificateFixture(t *testing.T) (string, string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com", "*.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
}

type fixtureDNS struct {
	present, wait, cleanup int
	stop                   bool
}

func (d *fixtureDNS) Present(_ context.Context, ch Challenge) (json.RawMessage, error) {
	if ch.Name == "" || ch.Value == "" {
		return nil, errors.New("invalid challenge")
	}
	d.present++
	return json.RawMessage(`{"record_id":"owned-record"}`), nil
}
func (d *fixtureDNS) Wait(_ context.Context, _ Challenge) error {
	d.wait++
	if d.stop {
		return errors.New("DNS not propagated")
	}
	return nil
}
func (d *fixtureDNS) Cleanup(_ context.Context, ch Challenge) error {
	if string(ch.Receipt) != `{"record_id":"owned-record"}` {
		return errors.New("cleanup receipt missing")
	}
	d.cleanup++
	return nil
}
func zipFixture(t *testing.T, chain, key, extension string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, value := range map[string]string{"Nginx/cert" + extension: chain, "Nginx/cert.key": key} {
		f, e := w.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		_, e = f.Write([]byte(value))
		if e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

func TestACMECheckpointResume(t *testing.T) {
	var endpoint, chain string
	orderStatus := "pending"
	authStatus := "pending"
	orders, finalized := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-fixture")
		w.Header().Set("Content-Type", "application/json")
		respond := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		switch r.URL.Path {
		case "/directory":
			respond(map[string]string{"newNonce": endpoint + "/nonce", "newAccount": endpoint + "/account/new", "newOrder": endpoint + "/order/new", "revokeCert": endpoint + "/revoke"})
		case "/nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/account/new":
			w.Header().Set("Location", endpoint+"/account/1")
			w.WriteHeader(http.StatusCreated)
			respond(map[string]any{"status": "valid"})
		case "/account/1":
			respond(map[string]any{"status": "valid"})
		case "/order/new":
			orders++
			w.Header().Set("Location", endpoint+"/order/1")
			w.WriteHeader(http.StatusCreated)
			respond(map[string]any{"identifiers": []any{map[string]string{"type": "dns", "value": "example.com"}}, "status": orderStatus, "authorizations": []string{endpoint + "/auth/1"}, "finalize": endpoint + "/finalize/1"})
		case "/order/1":
			respond(map[string]any{"identifiers": []any{map[string]string{"type": "dns", "value": "example.com"}}, "status": orderStatus, "authorizations": []string{endpoint + "/auth/1"}, "finalize": endpoint + "/finalize/1", "certificate": endpoint + "/certificate/1"})
		case "/auth/1":
			respond(map[string]any{"status": authStatus, "identifier": map[string]string{"type": "dns", "value": "example.com"}, "challenges": []any{map[string]string{"type": "dns-01", "url": endpoint + "/challenge/1", "status": authStatus, "token": "validation-token"}}})
		case "/challenge/1":
			authStatus = "valid"
			orderStatus = "ready"
			respond(map[string]string{"status": "valid", "type": "dns-01", "url": endpoint + "/challenge/1"})
		case "/finalize/1":
			var jws map[string]string
			if e := json.NewDecoder(r.Body).Decode(&jws); e != nil {
				t.Error(e)
			}
			payload, e := base64.RawURLEncoding.DecodeString(jws["payload"])
			if e != nil {
				t.Error(e)
			}
			var body map[string]string
			_ = json.Unmarshal(payload, &body)
			csrDER, e := base64.RawURLEncoding.DecodeString(body["csr"])
			if e != nil {
				t.Error(e)
			}
			csr, e := x509.ParseCertificateRequest(csrDER)
			if e != nil {
				t.Error(e)
				w.WriteHeader(500)
				return
			}
			if e = csr.CheckSignature(); e != nil {
				t.Error(e)
			}
			issuer, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if e != nil {
				t.Error(e)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: csr.Subject, DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
			der, e := x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, issuer)
			if e != nil {
				t.Error(e)
			}
			chain = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			finalized++
			orderStatus = "valid"
			respond(map[string]string{"status": "valid", "certificate": endpoint + "/certificate/1"})
		case "/certificate/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write([]byte(chain))
		default:
			t.Errorf("unexpected ACME route %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	endpoint = server.URL
	provider, e := New("customacme", map[string]string{"directory": endpoint + "/directory", "email": "admin@example.com"}, Options{HTTPClient: server.Client(), PollInterval: time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	cp := &Checkpoint{}
	dns := &fixtureDNS{stop: true}
	snapshots := 0
	save := func(_ context.Context, c Checkpoint) error {
		snapshots++
		if c.Provider != "customacme" {
			t.Error("provider omitted")
		}
		return nil
	}
	request := Request{Domains: []string{"example.com"}, KeyType: "ECC", KeySize: 256}
	if _, e = provider.Issue(context.Background(), request, cp, dns, save); e == nil {
		t.Fatal("expected propagation pause")
	}
	if orders != 1 || dns.present != 1 || cp.OrderURL == "" || !cp.Challenges[0].Presented {
		t.Fatalf("order/challenge checkpoint not saved: err=%v orders=%d present=%d", e, orders, dns.present)
	}
	dns.stop = false
	result, e := provider.Issue(context.Background(), request, cp, dns, save)
	if e != nil {
		t.Fatal(e)
	}
	if orders != 1 || finalized != 1 || dns.present != 1 || dns.cleanup != 1 || cp.Stage != "complete" || result.Subject != "example.com" || snapshots < 5 {
		t.Fatalf("resume duplicated side effects: orders=%d finalize=%d DNS=%+v stage=%s", orders, finalized, dns, cp.Stage)
	}
	if _, e = provider.Issue(context.Background(), Request{Domains: []string{"other.example.com"}, KeyType: "ECC", KeySize: 256}, cp, dns, save); e == nil {
		t.Fatal("changed request was accepted")
	}
}

func TestCloudIssuerFlows(t *testing.T) {
	chain, key := certificateFixture(t)
	for _, kind := range []string{"tencent", "aliyun", "ucloud", "huoshan"} {
		t.Run(kind, func(t *testing.T) {
			var endpoint string
			created := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/download.zip" {
					_, _ = w.Write(zipFixture(t, chain, key, map[string]string{"tencent": ".crt", "ucloud": ".pem"}[kind]))
					return
				}
				var body map[string]any
				action := ""
				switch kind {
				case "tencent":
					action = r.Header.Get("X-TC-Action")
					if !strings.HasPrefix(r.Header.Get("Authorization"), "TC3-HMAC-SHA256 Credential=fixture-id/") {
						t.Error("missing Tencent signature")
					}
					_ = json.NewDecoder(r.Body).Decode(&body)
				case "aliyun":
					_ = r.ParseForm()
					action = r.Form.Get("Action")
					if r.Form.Get("Signature") == "" {
						t.Error("missing Aliyun signature")
					}
				case "ucloud":
					_ = json.NewDecoder(r.Body).Decode(&body)
					action = scalar(body["Action"])
					if scalar(body["Signature"]) == "" {
						t.Error("missing UCloud signature")
					}
				case "huoshan":
					action = r.URL.Query().Get("Action")
					if !strings.HasPrefix(r.Header.Get("Authorization"), "HMAC-SHA256 Credential=fixture-id/") {
						t.Error("missing Volcengine signature")
					}
				}
				response := map[string]any{}
				var result any = response
				switch action {
				case "DescribeCertificates", "ListInstances", "GetCertificateList":
					if kind == "aliyun" {
						response["InstanceList"] = []any{map[string]string{"InstanceId": "instance-1"}}
					}
				case "ApplyCertificate":
					created++
					response["CertificateId"] = "cert-1"
				case "DescribeCertificate":
					response = map[string]any{"Status": 1, "OrderId": "order-1", "DvAuthDetail": map[string]any{"DvAuths": []any{map[string]string{"DvAuthKey": "_validation.example.com", "DvAuthVerifyType": "TXT", "DvAuthValue": "validation-value"}}}}
				case "ModifyCertificatesExpiringNotificationSwitch", "UpdateInstance", "ComplementCSRInfo", "CompleteCertificate", "CertificateProgressInstanceOrder":
				case "DescribeDownloadCertificateUrl":
					response["DownloadCertificateUrl"] = endpoint + "/download.zip"
				case "GetInstanceSummary":
					response["InactiveCount"] = 1
				case "ListContact":
					response["ContactList"] = []any{map[string]string{"ContactId": "contact-1"}}
				case "GetTaskAttribute":
					response["TaskStatus"] = "success"
				case "GetInstanceDetail":
					response = map[string]any{"Status": "normal", "CertificateId": "cert-1", "DomainValidationList": []any{map[string]string{"ValidationKey": "_validation", "RootDomain": "example.com", "ValidationType": "TXT", "ValidationValue": "validation-value"}}}
				case "GetUserCertificateDetail":
					response["Cert"] = chain
					response["Key"] = key
				case "PurchaseCertificate":
					created++
					response["CertificateID"] = "cert-1"
				case "GetDVAuthInfo":
					response["Auths"] = []any{map[string]string{"AuthKey": "_validation.example.com", "AuthType": "DNS_TXT", "AuthValue": "validation-value"}}
				case "GetCertificateDetailInfo":
					response["CertificateInfo"] = map[string]string{"StateCode": "COMPLETED"}
				case "DownloadCertificate":
					response["CertificateUrl"] = endpoint + "/download.zip"
				case "CertificateGetOrganization":
					response["content"] = []any{map[string]string{"id": "organization-1"}}
				case "QuickApplyCertificate":
					created++
					result = "instance-1"
				case "CertificateGetDcvParam":
					response["validation_type"] = "dns_txt"
					response["domains_to_be_validated"] = []any{map[string]string{"validation_domain": "_validation.example.com", "value": "validation-value"}}
				case "CertificateGetInstance":
					response["content"] = []any{map[string]any{"order_status": 300, "certificate_exist": 1, "ssl": map[string]any{"certificate": map[string]any{"chain": []string{chain}, "private_key": key}}}}
				default:
					t.Errorf("unexpected %s action %s", kind, action)
					w.WriteHeader(500)
					return
				}
				if action != "QuickApplyCertificate" {
					result = response
				}
				w.Header().Set("Content-Type", "application/json")
				switch kind {
				case "tencent":
					_ = json.NewEncoder(w).Encode(map[string]any{"Response": result})
				case "aliyun":
					_ = json.NewEncoder(w).Encode(result)
				case "ucloud":
					response["RetCode"] = 0
					_ = json.NewEncoder(w).Encode(response)
				case "huoshan":
					_ = json.NewEncoder(w).Encode(map[string]any{"Result": result, "ResponseMetadata": map[string]string{}})
				}
			}))
			defer server.Close()
			endpoint = server.URL
			cfg := map[string]string{"SecretId": "fixture-id", "SecretKey": "fixture-secret", "AccessKeyId": "fixture-id", "AccessKeySecret": "fixture-secret", "SecretAccessKey": "fixture-secret", "PublicKey": "fixture-id", "PrivateKey": "fixture-secret", "email": "admin@example.com", "phone": "00000000000", "username": "Fixture"}
			p, e := New(kind, cfg, Options{Endpoint: endpoint, HTTPClient: server.Client(), PollInterval: time.Millisecond})
			if e != nil {
				t.Fatal(e)
			}
			cp := &Checkpoint{}
			dns := &fixtureDNS{}
			save := func(_ context.Context, c Checkpoint) error {
				if c.Metadata == nil {
					t.Error("metadata checkpoint missing")
				}
				return nil
			}
			result, e := p.Issue(context.Background(), Request{Domains: []string{"example.com"}, KeyType: "ECC", KeySize: 256}, cp, dns, save)
			if e != nil {
				t.Fatal(e)
			}
			if result.Subject != "example.com" || cp.Stage != "complete" || dns.present != 1 || dns.cleanup != 1 || created != 1 {
				t.Fatalf("bad issuance state result=%+v stage=%s DNS=%+v created=%d", result, cp.Stage, dns, created)
			}
		})
	}
}

func TestInputAndZIPValidation(t *testing.T) {
	for _, domain := range []string{"bad..example.com", "-bad.example.com", "bad_.example.com", "*.com", "1.2.3.4", "bad.example.com/path"} {
		_, e := validateDomains([]string{domain}, 100, true)
		if e == nil {
			t.Errorf("accepted %s", domain)
		}
	}
	if _, e := generateKey("invalid", 2048); e == nil {
		t.Error("invalid key type accepted")
	}
	chain, key := certificateFixture(t)
	if _, e := ParseCertificateZIP(zipFixture(t, chain, key, ".crt"), ".crt"); e != nil {
		t.Fatal(e)
	}
	_, other := certificateFixture(t)
	if _, e := ParseResult(chain, other); e == nil {
		t.Error("mismatched key accepted")
	}
	registered := 0
	for _, d := range Catalog {
		if d.Registered {
			registered++
		}
	}
	if registered != 8 {
		t.Fatalf("registered issuers = %d", registered)
	}
}

func TestTencentRevocationCheckpointAndCleanup(t *testing.T) {
	calls, polls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := map[string]any{}
		switch r.Header.Get("X-TC-Action") {
		case "RevokeCertificate":
			calls++
			value["RevokeDomainValidateAuths"] = []any{map[string]any{"DomainValidateAuthDomain": "example.com", "DomainValidateAuthKey": "_revoke.example.com", "DomainValidateAuthValue": "revoke-owned"}}
		case "DescribeCertificate":
			polls++
			value["Status"] = 10
		default:
			t.Errorf("unexpected revocation action %s", r.Header.Get("X-TC-Action"))
		}
		json.NewEncoder(w).Encode(map[string]any{"Response": value})
	}))
	defer server.Close()
	dns := &fixtureDNS{stop: true}
	var saved Checkpoint
	save := func(_ context.Context, cp Checkpoint) error {
		raw, _ := json.Marshal(cp)
		return json.Unmarshal(raw, &saved)
	}
	p, err := New("tencent", map[string]string{"SecretId": "fixture", "SecretKey": "fixture"}, Options{Endpoint: server.URL, HTTPClient: server.Client(), DNS: dns, SaveCheckpoint: save})
	if err != nil {
		t.Fatal(err)
	}
	cp := Checkpoint{Provider: "tencent", Stage: "complete", Metadata: map[string]any{"CertificateId": "fixture-id"}}
	if err = p.Revoke(context.Background(), &cp, ""); err == nil || dns.present != 1 || calls != 1 || polls != 0 {
		t.Fatalf("revocation pause err=%v present=%d calls=%d polls=%d", err, dns.present, calls, polls)
	}
	if !saved.Challenges[0].Presented || saved.Metadata["revoke_requested"] != true {
		t.Error("revocation DNS receipt not persisted")
	}
	cp = saved
	dns.stop = false
	if err = p.Revoke(context.Background(), &cp, ""); err != nil || dns.present != 1 || dns.cleanup != 1 || calls != 1 || cp.Stage != "revoked" {
		t.Fatalf("revocation resume err=%v present=%d cleanup=%d calls=%d stage=%s", err, dns.present, dns.cleanup, calls, cp.Stage)
	}
	if err = p.Revoke(context.Background(), &cp, ""); err != nil || dns.cleanup != 1 || calls != 1 {
		t.Fatal("revocation replay repeated external writes")
	}
	if err = p.Revoke(context.Background(), nil, ""); err == nil {
		t.Error("nil revocation checkpoint accepted")
	}
}

func TestCloudIssuerRejectsUnsupportedKeyBeforeWrites(t *testing.T) {
	for _, kind := range []string{"tencent", "aliyun", "ucloud", "huoshan"} {
		t.Run(kind, func(t *testing.T) {
			p, err := New(kind, nil, Options{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Issue(context.Background(), Request{Domains: []string{"example.com"}, KeyType: "unknown", KeySize: 1}, &Checkpoint{}, &fixtureDNS{}, func(context.Context, Checkpoint) error { return nil })
			if err == nil || !strings.Contains(err.Error(), "key type") {
				t.Fatalf("unexpected key validation %v", err)
			}
		})
	}
}

func TestCloudOrderLostResponseCannotCreateAnotherOrder(t *testing.T) {
	orders := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-TC-Action") == "ApplyCertificate" {
			orders++
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"Response":{}}`))
			return
		}
		w.Write([]byte(`{"Response":{}}`))
	}))
	defer server.Close()
	p, err := New("tencent", map[string]string{"SecretId": "fixture", "SecretKey": "fixture", "email": "fixture@example.invalid"}, Options{Endpoint: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	var saved Checkpoint
	save := func(_ context.Context, cp Checkpoint) error {
		raw, _ := json.Marshal(cp)
		saved = Checkpoint{}
		return json.Unmarshal(raw, &saved)
	}
	cp := Checkpoint{}
	request := Request{Domains: []string{"example.com"}, KeyType: "RSA", KeySize: 2048}
	_, err = p.Issue(context.Background(), request, &cp, &fixtureDNS{}, save)
	var unknown *UnknownError
	if !errors.As(err, &unknown) || orders != 1 || saved.Metadata["submitted:ApplyCertificate"] != true {
		t.Fatal("lost order response not durably fenced", err, orders, saved.Metadata)
	}
	cp = saved
	_, err = p.Issue(context.Background(), request, &cp, &fixtureDNS{}, save)
	if !errors.As(err, &unknown) || orders != 1 {
		t.Fatal("lost response caused duplicate cloud order", err, orders)
	}
}
