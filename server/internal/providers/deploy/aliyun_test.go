package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func aliyunFixturePair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1234567), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com", "www.example.com"}, NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}
func TestAliyunProductBindings(t *testing.T) {
	chain, key := aliyunFixturePair(t)
	for _, product := range []string{"cdn", "dcdn", "live", "ddoscoo", "upload", "oss", "api", "vod", "fc", "fc2", "esa", "esa_saas", "waf", "wafres", "waf2", "clb", "alb", "nlb", "ga"} {
		t.Run(product, func(t *testing.T) {
			persisted := false
			actions := []string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if product == "oss" && r.URL.Query().Has("cname") {
					if !strings.HasPrefix(r.Header.Get("Authorization"), "OSS fixture-key:") {
						t.Error("missing OSS signature")
					}
					if !persisted {
						t.Error("OSS bind before checkpoint")
					}
					w.WriteHeader(200)
					return
				}
				if strings.Contains(r.URL.Path, "custom-domains") {
					if !strings.HasPrefix(r.Header.Get("Authorization"), "ACS3-HMAC-SHA256 Credential=fixture-key,") {
						t.Error("missing ACS3 signature")
					}
					if r.Method == http.MethodGet {
						json.NewEncoder(w).Encode(map[string]any{"protocol": "HTTP", "certConfig": map[string]any{}, "routeConfig": map[string]any{"routes": []any{}}})
						return
					}
					var body map[string]any
					json.NewDecoder(r.Body).Decode(&body)
					if text(obj(body["certConfig"])["privateKey"]) != key || text(body["protocol"]) != "HTTP,HTTPS" {
						t.Error("FC certificate or protocol lost")
					}
					actions = append(actions, "UpdateCustomDomain")
					json.NewEncoder(w).Encode(map[string]any{})
					return
				}
				r.ParseForm()
				params := map[string]string{}
				for k, v := range r.Form {
					params[k] = v[0]
				}
				signature := params["Signature"]
				delete(params, "Signature")
				mac := hmac.New(sha1.New, []byte("fixture-secret&"))
				mac.Write([]byte(r.Method + "&%2F&" + aliyunEscape(aliyunQuery(params))))
				if signature != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
					t.Error("RPC signature mismatch")
				}
				action := r.Form.Get("Action")
				actions = append(actions, action)
				response := map[string]any{}
				switch action {
				case "ListUserCertificateOrder":
					response["CertificateOrderList"] = []any{}
				case "UploadUserCertificate":
					if r.Form.Get("Cert") != chain || r.Form.Get("Key") != key {
						t.Error("CAS PEM changed")
					}
					response["CertId"] = "cas1"
				case "ListSites":
					response["Sites"] = []any{map[string]any{"SiteName": "example.com", "SiteId": 123}}
				case "ListCertificates":
					response["Result"] = []any{}
				case "ListInstanceQuotasWithUsage":
					response["Quotas"] = []any{map[string]any{"Usage": 0, "QuotaValue": 5}}
				case "SetCertificate":
					response["Id"] = "esa1"
				case "ListCustomHostnames":
					response["Hostnames"] = []any{map[string]any{"Hostname": "www.example.com", "SiteId": 123, "HostnameId": 456}}
				case "DescribeInstance":
					response["InstanceId"] = "waf1"
				case "DescribeInstanceInfo":
					response["InstanceInfo"] = map[string]any{"InstanceId": "waf2"}
				case "DescribeDomainDetail":
					response["Listen"] = map[string]any{"CertId": "old"}
					response["Redirect"] = map[string]any{"BackendPorts": []any{map[string]any{"Protocol": "http", "BackendPort": 80}}, "AllBackends": []string{"192.0.2.1"}}
				case "DescribeCloudResourceList":
					response["CloudResourceList"] = []any{map[string]any{"id": "protected"}}
				case "DescribeResourceInstanceCerts":
					response["Certs"] = []any{}
				case "DescribeServerCertificates":
					response["ServerCertificates"] = map[string]any{"ServerCertificate": []any{}}
				case "UploadServerCertificate":
					response["ServerCertificateId"] = "clb-cert"
				case "DescribeLoadBalancerHTTPSListenerAttribute":
					response["ServerCertificateId"] = "old"
				}
				if strings.HasPrefix(action, "Set") || strings.HasPrefix(action, "Modify") || strings.HasPrefix(action, "Update") || strings.HasPrefix(action, "Associate") || strings.HasPrefix(action, "CreateCertificate") {
					if product != "api" && product != "vod" && !persisted {
						t.Error("binding before CAS checkpoint")
					}
				}
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			cfg := map[string]string{"AccessKeyId": "fixture-key", "AccessKeySecret": "fixture-secret", "url": server.URL}
			provider, err := newAliyun(cfg, Options{HTTPClient: server.Client(), Now: func() time.Time { return time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC) }, Checkpoint: func(ctx context.Context, info Info) error { persisted = true; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			target := Target{Domains: []string{"www.example.com"}, Config: map[string]string{"product": product, "region": "cn-hangzhou", "regionid": "cn-hangzhou", "oss_endpoint": "oss-cn-hangzhou.aliyuncs.com", "oss_bucket": "fixture-bucket", "api_groupid": "api1", "fc_cname": "fixture.fc.aliyuncs.com", "esa_sitename": "example.com", "esa_saas_sitename": "www.example.com", "waf_resource_id": "cloud-resource-instance-a-b", "clb_id": "clb1", "clb_port": "443", "alb_listener_id": "alb1", "nlb_listener_id": "nlb1", "ga_id": "ga1", "ga_listener_id": "listener1"}}
			result, err := provider.Deploy(context.Background(), chain, key, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if product != "api" && product != "vod" && product != "fc" && product != "fc2" && text(result["cert_id"]) != "cas1" {
				t.Fatal("CAS checkpoint missing")
			}
			if len(actions) == 0 && product != "oss" {
				t.Fatal("no provider operations")
			}
		})
	}
}
func TestAliyunCheckpointFailurePreventsBinding(t *testing.T) {
	chain, key := aliyunFixturePair(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch r.Form.Get("Action") {
		case "ListUserCertificateOrder":
			fmt.Fprint(w, `{"CertificateOrderList":[]}`)
		case "UploadUserCertificate":
			fmt.Fprint(w, `{"CertId":"id-created"}`)
		default:
			calls++
			fmt.Fprint(w, `{}`)
		}
	}))
	defer server.Close()
	provider, _ := newAliyun(map[string]string{"AccessKeyId": "fixture-key", "AccessKeySecret": "fixture-secret", "url": server.URL}, Options{HTTPClient: server.Client(), Checkpoint: func(context.Context, Info) error { return errors.New("checkpoint failed") }})
	info, err := provider.Deploy(context.Background(), chain, key, Target{Config: map[string]string{"product": "cdn"}, Domains: []string{"example.com"}}, nil)
	if err == nil || calls != 0 || text(info["cert_id"]) != "id-created" {
		t.Fatalf("unsafe continuation: err=%v calls=%d info=%v", err, calls, info)
	}
}
func TestAliyunBatchDoesNotSkipLaterDomains(t *testing.T) {
	chain, key := aliyunFixturePair(t)
	bound := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch r.Form.Get("Action") {
		case "ListUserCertificateOrder":
			fmt.Fprint(w, `{"CertificateOrderList":[]}`)
		case "UploadUserCertificate":
			fmt.Fprint(w, `{"CertId":"id1"}`)
		default:
			domain := r.Form.Get("DomainName")
			bound = append(bound, domain)
			if domain == "fail.example.com" {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"Code":"Denied","Message":"denied"}`)
			} else {
				fmt.Fprint(w, `{}`)
			}
		}
	}))
	defer server.Close()
	provider, _ := newAliyun(map[string]string{"AccessKeyId": "fixture-key", "AccessKeySecret": "fixture-secret", "url": server.URL}, Options{HTTPClient: server.Client(), Checkpoint: func(context.Context, Info) error { return nil }})
	_, err := provider.Deploy(context.Background(), chain, key, Target{Config: map[string]string{"product": "cdn"}, Domains: []string{"fail.example.com", "ok.example.com"}}, nil)
	var partial *PartialError
	if !errors.As(err, &partial) || partial.Failed != 1 || partial.Succeeded != 1 || len(bound) != 2 {
		t.Fatalf("partial result incorrect %v %v", err, bound)
	}
}
func TestAliyunSaaSRejectsAmbiguousTargets(t *testing.T) {
	chain, key := aliyunFixturePair(t)
	updates := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch r.Form.Get("Action") {
		case "ListUserCertificateOrder":
			fmt.Fprint(w, `{"CertificateOrderList":[]}`)
		case "UploadUserCertificate":
			fmt.Fprint(w, `{"CertId":"id1"}`)
		case "ListSites":
			fmt.Fprint(w, `{"Sites":[{"SiteId":123,"SiteName":"example.com"}]}`)
		case "ListCustomHostnames":
			fmt.Fprint(w, `{"Hostnames":[{"SiteId":123,"Hostname":"www.example.com","HostnameId":1},{"SiteId":123,"Hostname":"www.example.com","HostnameId":2}]}`)
		default:
			updates++
			fmt.Fprint(w, `{}`)
		}
	}))
	defer server.Close()
	provider, _ := newAliyun(map[string]string{"AccessKeyId": "fixture-key", "AccessKeySecret": "fixture-secret", "url": server.URL}, Options{HTTPClient: server.Client(), Checkpoint: func(context.Context, Info) error { return nil }})
	_, err := provider.Deploy(context.Background(), chain, key, Target{Config: map[string]string{"product": "esa_saas", "esa_sitename": "example.com", "esa_saas_sitename": "www.example.com"}}, nil)
	if err == nil || updates != 0 {
		t.Fatal("ambiguous SaaS hostname was updated")
	}
}

func TestAliyunACS3AndOSSIndependentSignatures(t *testing.T) {
	checkedACS, checkedOSS := false, false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(r.Header.Get("Authorization"), "OSS ") {
			canonical := "POST\n\n" + r.Header.Get("Content-Type") + "\n" + r.Header.Get("Date") + "\n/fixture-bucket/?cname&comp=add"
			mac := hmac.New(sha1.New, []byte("fixture-secret"))
			mac.Write([]byte(canonical))
			expected := "OSS fixture-key:" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
			if r.Header.Get("Authorization") != expected {
				t.Error("OSS signature mismatch")
			}
			checkedOSS = true
		} else {
			auth := strings.TrimPrefix(r.Header.Get("Authorization"), "ACS3-HMAC-SHA256 ")
			values := map[string]string{}
			for _, f := range strings.Split(auth, ",") {
				k, v, ok := strings.Cut(f, "=")
				if ok {
					values[k] = v
				}
			}
			canonicalHeaders := ""
			for _, name := range strings.Split(values["SignedHeaders"], ";") {
				v := r.Header.Get(name)
				if name == "host" {
					v = r.Host
				}
				canonicalHeaders += name + ":" + strings.TrimSpace(v) + "\n"
			}
			sum := sha256.Sum256(raw)
			bodyHash := hex.EncodeToString(sum[:])
			canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + r.URL.RawQuery + "\n" + canonicalHeaders + "\n" + values["SignedHeaders"] + "\n" + bodyHash
			hash := sha256.Sum256([]byte(canonical))
			mac := hmac.New(sha256.New, []byte("fixture-secret"))
			mac.Write([]byte("ACS3-HMAC-SHA256\n" + hex.EncodeToString(hash[:])))
			if values["Signature"] != hex.EncodeToString(mac.Sum(nil)) {
				t.Error("ACS3 signature mismatch")
			}
			checkedACS = true
		}
		json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer server.Close()
	provider, err := newAliyun(map[string]string{"url": server.URL, "AccessKeyId": "fixture-key", "AccessKeySecret": "fixture-secret"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	p := provider.(*aliyunProvider)
	if _, err = p.acs3(context.Background(), "fixture.aliyuncs.com", "2023-03-30", http.MethodPut, "UpdateCustomDomain", "/2023-03-30/custom-domains/example.com", map[string]any{"privateKey": "fixture-key"}); err != nil {
		t.Fatal(err)
	}
	if err = p.oss(context.Background(), "oss-cn-hangzhou.aliyuncs.com", "fixture-bucket", "example.com", "fixture-id"); err != nil {
		t.Fatal(err)
	}
	if !checkedACS || !checkedOSS {
		t.Fatal("Aliyun signatures not checked")
	}
}

func TestAliyunValidationPrecedesCertificateUpload(t *testing.T) {
	chain, key := aliyunFixturePair(t)
	provider, err := newAliyun(map[string]string{"AccessKeyId": "fixture-key", "AccessKeySecret": "fixture-secret"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Deploy(context.Background(), chain, key, Target{Config: map[string]string{"product": "clb", "clb_id": "fixture-clb"}}, nil); err == nil || !strings.Contains(err.Error(), "clb_port") {
		t.Fatalf("Aliyun target validation=%v", err)
	}
}
