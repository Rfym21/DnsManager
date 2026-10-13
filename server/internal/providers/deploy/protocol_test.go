package deploy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The expected wire contracts below are independent of provider.call helpers.
// Each factory is exercised through Deploy, including its discovery/login work.
type deployWireStep struct {
	method, path    string
	query           map[string]string
	fields          map[string]string
	headers         map[string]string
	response        string
	status          int
	responseHeaders map[string]string
	write           bool
	check           func(*testing.T, *http.Request, []byte)
}
type deployWireCase struct {
	kind   string
	cfg    map[string]string
	target map[string]string
	prior  Info
	steps  []deployWireStep
	result map[string]string
}

func wireStep(method, path, response string) deployWireStep {
	return deployWireStep{method: method, path: path, response: response}
}
func wireWrite(method, path, response string, fields map[string]string) deployWireStep {
	s := wireStep(method, path, response)
	s.write, s.fields = true, fields
	return s
}
func wireMD5(value string) string { sum := md5.Sum([]byte(value)); return hex.EncodeToString(sum[:]) }
func wireSHA(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func wireHMAC(hash string, key []byte, value string) []byte {
	var mac io.Writer
	var sum func() []byte
	switch hash {
	case "md5":
		h := hmac.New(md5.New, key)
		mac, sum = h, func() []byte { return h.Sum(nil) }
	case "sha1":
		h := hmac.New(sha1.New, key)
		mac, sum = h, func() []byte { return h.Sum(nil) }
	default:
		h := hmac.New(sha256.New, key)
		mac, sum = h, func() []byte { return h.Sum(nil) }
	}
	_, _ = io.WriteString(mac, value)
	return sum()
}
func wireField(value any, path string) any {
	parts := strings.Split(path, ".")
	for index, part := range parts {
		switch item := value.(type) {
		case map[string]any:
			if exact, exists := item[strings.Join(parts[index:], ".")]; exists {
				return exact
			}
			value = item[part]
		case []any:
			n, e := strconv.Atoi(part)
			if e != nil || n < 0 || n >= len(item) {
				return nil
			}
			value = item[n]
		default:
			return nil
		}
	}
	return value
}
func wireBody(t *testing.T, req *http.Request, raw []byte) map[string]any {
	t.Helper()
	if strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/form-data") {
		copy := req.Clone(req.Context())
		copy.Body = io.NopCloser(bytes.NewReader(raw))
		if e := copy.ParseMultipartForm(1 << 20); e != nil {
			t.Fatal(e)
		}
		defer copy.MultipartForm.RemoveAll()
		out := map[string]any{}
		for name, values := range copy.MultipartForm.Value {
			out[name] = values[0]
		}
		for name, files := range copy.MultipartForm.File {
			file, e := files[0].Open()
			if e != nil {
				t.Fatal(e)
			}
			data, e := io.ReadAll(file)
			file.Close()
			if e != nil {
				t.Fatal(e)
			}
			out[name] = string(data)
		}
		return out
	}
	if strings.HasPrefix(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		form, e := url.ParseQuery(string(raw))
		if e != nil {
			t.Fatal(e)
		}
		out := map[string]any{}
		for name, values := range form {
			out[name] = values[0]
		}
		return out
	}
	out := map[string]any{}
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if e := decoder.Decode(&value); e != nil {
			t.Fatal(e)
		}
		if list, ok := value.([]any); ok {
			out["items"] = list
		} else {
			out, _ = value.(map[string]any)
		}
	}
	return out
}

func TestDeploymentHTTPProtocolMatrix(t *testing.T) {
	chain, key := deployFixture(t)
	cases := deploymentWireCases(t, chain, key)
	covered := map[string]bool{}
	for _, fixture := range cases {
		covered[fixture.kind] = true
	}
	for _, descriptor := range Catalog {
		if descriptor.ID != "local" && descriptor.ID != "ssh" && descriptor.ID != "ftp" && descriptor.ID != "fnos" && !covered[descriptor.ID] {
			t.Errorf("HTTP deployment provider %s has no protocol fixture", descriptor.ID)
		}
	}
	for _, fixture := range cases {
		t.Run(fixture.kind, func(t *testing.T) {
			for _, outcome := range []string{"success", "rejected", "throttled", "unknown"} {
				t.Run(outcome, func(t *testing.T) {
					var calls atomic.Int64
					writeIndex := -1
					for n, step := range fixture.steps {
						if step.write {
							writeIndex = n
							break
						}
					}
					if writeIndex < 0 {
						t.Fatal("fixture does not deploy certificate material")
					}
					server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						n := int(calls.Add(1)) - 1
						if n >= len(fixture.steps) {
							t.Errorf("unexpected %s %s", req.Method, req.URL.Path)
							w.WriteHeader(500)
							return
						}
						step := fixture.steps[n]
						if req.Method != step.method || req.URL.Path != step.path {
							t.Errorf("step %d: got %s %s, want %s %s", n, req.Method, req.URL.Path, step.method, step.path)
						}
						for name, want := range step.query {
							if req.URL.Query().Get(name) != want {
								t.Errorf("step %d query %s mismatch", n, name)
							}
						}
						for name, want := range step.headers {
							if req.Header.Get(name) != want {
								t.Errorf("step %d header %s mismatch", n, name)
							}
						}
						raw, e := io.ReadAll(req.Body)
						if e != nil {
							t.Error(e)
							return
						}
						if len(step.fields) > 0 {
							body := wireBody(t, req, raw)
							for name, want := range step.fields {
								if text(wireField(body, name)) != want {
									t.Errorf("step %d payload %s mismatch", n, name)
								}
							}
						}
						checkDeploymentWireAuth(t, fixture.kind, fixture.cfg, req, raw)
						if step.check != nil {
							step.check(t, req, raw)
						}
						if n == writeIndex && outcome != "success" {
							status := map[string]int{"rejected": 403, "throttled": 429, "unknown": 502}[outcome]
							w.WriteHeader(status)
							_, _ = io.WriteString(w, `{"message":"fixture refusal"}`)
							return
						}
						for name, value := range step.responseHeaders {
							w.Header().Set(name, value)
						}
						if step.status != 0 {
							w.WriteHeader(step.status)
						}
						_, _ = io.WriteString(w, step.response)
					}))
					defer server.Close()
					cfg := map[string]string{"url": server.URL}
					for name, value := range fixture.cfg {
						cfg[name] = value
					}
					if fixture.kind == "k8s" {
						cfg["kubeconfig"] = wireKubeconfig(server.URL)
					}
					if fixture.kind == "qiniu" {
						cfg["pili_endpoint"] = server.URL
					}
					provider, e := New(fixture.kind, cfg, Options{HTTPClient: server.Client(), Now: func() time.Time { return time.Date(2026, 10, 13, 1, 2, 3, 0, time.UTC) }, Checkpoint: func(context.Context, Info) error { return nil }})
					if e != nil {
						t.Fatal(e)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					info, e := provider.Deploy(ctx, chain, key, Target{Domains: []string{"example.com"}, Config: fixture.target}, fixture.prior)
					if outcome == "success" {
						if e != nil {
							t.Fatal(e)
						}
						if int(calls.Load()) != len(fixture.steps) {
							t.Errorf("got %d requests, want %d", calls.Load(), len(fixture.steps))
						}
						for name, want := range fixture.result {
							if text(info[name]) != want {
								t.Errorf("result %s mismatch", name)
							}
						}
						return
					}
					if e == nil {
						t.Fatal("remote failure reported as success")
					}
					expectedCalls := writeIndex + 1
					if fixture.kind == "s3storage" {
						expectedCalls = len(fixture.steps)
					}
					if int(calls.Load()) != expectedCalls {
						t.Errorf("remote write continued after failed response: %d requests", calls.Load())
					}
					var rejected *RejectedError
					var unknown interface{ UnknownResult() bool }
					if outcome == "unknown" {
						if errors.As(e, &rejected) || errors.As(e, &unknown) && !unknown.UnknownResult() {
							t.Fatalf("ambiguous response classified as confirmed rejection: %v", e)
						}
					} else if partial, ok := e.(*PartialError); ok {
						if partial.Unknown {
							t.Fatal("explicit HTTP rejection classified as unknown")
						}
					} else if !errors.As(e, &rejected) || rejected.Retryable != (outcome == "throttled") {
						t.Fatalf("explicit rejection lost classification: %v", e)
					}
				})
			}
		})
	}
}

func wireKubeconfig(endpoint string) string {
	return "current-context: fixture\ncontexts:\n- name: fixture\n  context: {cluster: fixture, user: fixture}\nclusters:\n- name: fixture\n  cluster: {server: " + endpoint + "}\nusers:\n- name: fixture\n  user: {token: fixture-token}\n"
}

func deploymentWireCases(t *testing.T, chain, key string) []deployWireCase {
	t.Helper()
	cert64, key64 := base64.StdEncoding.EncodeToString([]byte(chain)), base64.StdEncoding.EncodeToString([]byte(key))
	cases := []deployWireCase{}
	add := func(kind string, cfg, target map[string]string, steps ...deployWireStep) {
		cases = append(cases, deployWireCase{kind: kind, cfg: cfg, target: target, steps: steps})
	}
	for _, kind := range []string{"btpanel", "mwpanel", "ratpanel", "acepanel", "btwin", "btwaf"} {
		path, response, fields := "/config", `{"status":true}`, map[string]string{"privateKey": key, "certPem": chain}
		cfg := map[string]string{"key": "fixture-secret", "appid": "fixture-app", "appsecret": "fixture-secret", "id": "fixture-id", "token": "fixture-secret"}
		query := map[string]string{}
		switch kind {
		case "btpanel":
			query["action"] = "SavePanelSSL"
		case "mwpanel":
			path = "/setting/save_panel_ssl"
			fields["choose"] = "local"
		case "ratpanel", "acepanel":
			path, response, fields = "/api/setting/cert", `{"msg":"success"}`, map[string]string{"cert": chain, "key": key}
		case "btwin":
			path, fields = "/config/set_panel_ssl", map[string]string{"ssl_key": key, "ssl_pem": chain}
		case "btwaf":
			path, response, fields = "/api/config/set_cert", `{"code":0,"res":{}}`, map[string]string{"certContent": chain, "keyContent": key}
		}
		s := wireWrite("POST", path, response, fields)
		s.query = query
		add(kind, cfg, map[string]string{"type": "1"}, s)
	}
	add("xp", map[string]string{"apikey": "fixture-secret"}, map[string]string{"sites": "example.com"},
		wireStep("GET", "/openApi/siteList", `{"code":1000,"data":[{"id":9,"name":"example.com"}]}`),
		wireWrite("POST", "/openApi/setSSL", `{"code":1000,"data":{}}`, map[string]string{"id": "9", "key": key, "pem": chain}))
	add("lucky", map[string]string{"opentoken": "fixture-secret"}, map[string]string{},
		wireStep("GET", "/api/ssl", `{"ret":0,"list":[{"Key":"cert-9","Remark":"preserve","CertsInfo":{"Domains":["example.com"]}}]}`),
		wireWrite("PUT", "/api/ssl", `{"ret":0}`, map[string]string{"Key": "cert-9", "CertBase64": cert64, "KeyBase64": key64, "Remark": "preserve"}))
	add("safeline", map[string]string{"token": "fixture-secret"}, map[string]string{},
		wireStep("GET", "/api/open/cert", `{"data":{"nodes":[{"id":9,"domains":["example.com"]}]}}`),
		wireWrite("POST", "/api/open/cert", `{"data":{"id":9}}`, map[string]string{"id": "9", "manual.crt": chain, "manual.key": key, "type": "2"}))
	add("opanel", map[string]string{"key": "fixture-secret", "version": "v2"}, map[string]string{"id": "9"},
		wireWrite("POST", "/api/v2/websites/ssl/upload", `{"code":200,"data":{"id":9}}`, map[string]string{"sslID": "9", "type": "paste", "certificate": chain, "privateKey": key}))
	add("proxmox", map[string]string{"api_user": "root@pam!fixture", "api_key": "fixture-secret"}, map[string]string{"node": "pve-1"},
		wireStep("GET", "/api2/json/nodes/pve-1/certificates/info", `{"data":[]}`),
		wireWrite("POST", "/api2/json/nodes/pve-1/certificates/custom", `{"data":null}`, map[string]string{"certificates": chain, "key": key, "force": "1", "restart": "1"}))
	add("directadmin", map[string]string{"username": "fixture-user", "password": "fixture-secret"}, map[string]string{"domain": "example.com"},
		wireWrite("POST", "/CMD_API_SSL", `{"error":0}`, map[string]string{"domain": "example.com", "action": "save", "type": "paste"}))
	add("uusec", map[string]string{"username": "fixture-user", "password": "fixture-secret"}, map[string]string{"id": "9", "name": "fixture-cert"},
		wireStep("POST", "/api/v1/users/login", `{"token":"fixture-token"}`),
		wireWrite("PUT", "/api/v1/certs", `"OK"`, map[string]string{"id": "9", "type": "1", "crt": chain, "key": key, "name": "fixture-cert"}))
	add("gcore", map[string]string{"apikey": "fixture-secret"}, map[string]string{"id": "9", "name": "fixture-cert"},
		wireWrite("PUT", "/cdn/sslData/9", `{}`, map[string]string{"name": "fixture-cert", "sslCertificate": chain, "sslPrivateKey": key}))
	add("cachefly", map[string]string{"apikey": "fixture-secret"}, map[string]string{},
		wireWrite("POST", "/certificates", `{"id":"9"}`, map[string]string{"certificate": chain, "certificateKey": key}))
	add("axisnow", map[string]string{"token": "fixture-secret"}, map[string]string{"id": "9"},
		wireWrite("PUT", "/client/v1/certificates/9", `{"success":true,"result":{}}`, map[string]string{"certificate": chain, "private_key": key}))
	add("rainyun", map[string]string{"apikey": "fixture-secret"}, map[string]string{"id": "9"},
		wireWrite("PUT", "/product/sslcenter/9", `{"code":200,"data":{}}`, map[string]string{"cert": chain, "key": key}))
	bai := wireWrite("POST", "/v2/domain/certificate", `{"code":0,"data":{}}`, map[string]string{"cert_id": "9", "certificate": chain, "key": key})
	bai.query = map[string]string{"token": "fixture-secret"}
	add("baishan", map[string]string{"token": "fixture-secret"}, map[string]string{"id": "9"}, bai)
	add("kuocai", map[string]string{"username": "fixture-user", "password": "fixture-secret"}, map[string]string{"id": "9"},
		wireStep("POST", "/login/loginUser", `{"code":"SUCCESS","data":"fixture-token"}`),
		wireWrite("POST", "/CdnDomainHttps/httpsConfiguration", `{"code":"SUCCESS","data":{}}`, map[string]string{"doMainId": "9", "https.certificate_value": chain, "https.private_key": key, "https.https_status": "on"}))
	add("cdnfly", map[string]string{"auth": "0", "api_key": "fixture-id", "api_secret": "fixture-secret"}, map[string]string{"id": "9"},
		wireWrite("PUT", "/v1/certs/9", `{"code":0,"data":{}}`, map[string]string{"type": "custom", "cert": chain, "key": key}))
	add("lecdn", map[string]string{"auth": "1", "api_key": "fixture-secret"}, map[string]string{"id": "9"},
		wireStep("GET", "/prod-api/certificate/9", `{"code":200,"data":{"name":"preserve","description":"preserve desc"}}`),
		wireWrite("PUT", "/prod-api/certificate/9", `{"code":200,"data":{}}`, map[string]string{"id": "9", "type": "upload", "ssl_pem": cert64, "ssl_key": key64, "name": "preserve", "description": "preserve desc"}))
	rows := base64.StdEncoding.EncodeToString([]byte(`[{"id":9,"name":"preserve","description":"preserve desc","serverName":"example.com"}]`))
	add("goedge", map[string]string{"usertype": "user", "accessKeyId": "fixture-id", "accessKey": "fixture-secret"}, map[string]string{},
		wireStep("POST", "/APIAccessTokenService/getAPIAccessToken", `{"code":200,"data":{"token":"fixture-token"}}`),
		wireStep("POST", "/SSLCertService/listSSLCerts", `{"code":200,"data":{"sslCertsJSON":"`+rows+`"}}`),
		wireWrite("POST", "/SSLCertService/updateSSLCert", `{"code":200,"data":{}}`, map[string]string{"sslCertId": "9", "certData": cert64, "keyData": key64, "name": "preserve", "description": "preserve desc"}))
	add("doge", map[string]string{"AccessKey": "fixture-id", "SecretKey": "fixture-secret"}, map[string]string{"domain": "example.com"},
		wireWrite("POST", "/cdn/cert/bind.json", `{"code":200,"data":{}}`, map[string]string{"id": "9", "domain": "example.com"}))
	cases[len(cases)-1].prior = Info{"cert_id": "9"}
	appendSessionWireCases(t, &cases, chain, key)
	appendCloudWireCases(t, &cases, chain, key)
	return cases
}
