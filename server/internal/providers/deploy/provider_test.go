package deploy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"strings"
	"testing"
	"time"
)

func deployFixture(t *testing.T) (string, string) {
	t.Helper()
	private, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com", "www.example.com", "*.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &private.PublicKey, private)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
}
func TestDeploymentCatalogContracts(t *testing.T) {
	if len(Catalog) != 50 {
		t.Fatalf("catalog size=%d", len(Catalog))
	}
	for _, d := range Catalog {
		if !d.Implemented || !Implemented(d.ID) {
			t.Errorf("provider %s absent from factory capability", d.ID)
		}
		for _, f := range append(d.Fields, d.TargetFields...) {
			values := map[string]bool{}
			for _, option := range f.Options {
				if option.Value == "" || strings.HasPrefix(option.Label, "{") {
					t.Errorf("invalid %s.%s option", d.ID, f.Name)
				}
				values[option.Value] = true
			}
			if f.Default != "" && len(f.Options) > 0 && !values[f.Default] {
				t.Errorf("invalid default %s.%s=%s", d.ID, f.Name, f.Default)
			}
		}
	}
}
func TestLocalDeploymentConfinementAndPFX(t *testing.T) {
	chain, key := deployFixture(t)
	root := t.TempDir()
	outside := t.TempDir()
	p, e := New("local", nil, Options{AllowedDirectories: []string{root}})
	if e != nil {
		t.Fatal(e)
	}
	target := Target{Config: map[string]string{"format": "pem", "pem_cert_file": filepath.Join(root, "cert.pem"), "pem_key_file": filepath.Join(root, "key.pem")}}
	if _, e = p.Deploy(context.Background(), chain, key, target, nil); e != nil {
		t.Fatal(e)
	}
	for name, mode := range map[string]os.FileMode{"cert.pem": 0644, "key.pem": 0600} {
		stat, e := os.Stat(filepath.Join(root, name))
		if e != nil || stat.Mode().Perm() != mode {
			t.Fatalf("%s mode=%v err=%v", name, stat, e)
		}
	}
	if e = os.Symlink(outside, filepath.Join(root, "escape")); e != nil {
		t.Fatal(e)
	}
	target.Config["pem_key_file"] = filepath.Join(root, "escape", "outside.key")
	if _, e = p.Deploy(context.Background(), chain, key, target, nil); e == nil {
		t.Fatal("symlink escape accepted")
	}
	target.Config["pem_key_file"] = filepath.Join(root, "symlink.key")
	if e = os.Symlink(filepath.Join(outside, "outside.key"), target.Config["pem_key_file"]); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Deploy(context.Background(), chain, key, target, nil); e == nil {
		t.Fatal("symlink destination accepted")
	}
	pfxPath := filepath.Join(root, "cert.pfx")
	if _, e = p.Deploy(context.Background(), chain, key, Target{Config: map[string]string{"format": "pfx", "pfx_file": pfxPath, "pfx_pass": "fixture-pass"}}, nil); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(pfxPath)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = pkcs12.DecodeChain(raw, "fixture-pass"); e != nil {
		t.Fatal(e)
	}
}
func TestSSHRequiresVerifiedHostKey(t *testing.T) {
	p, e := New("ssh", map[string]string{"host": "127.0.0.1", "username": "fixture", "password": "fixture"}, Options{})
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Validate(context.Background()); e == nil || !strings.Contains(e.Error(), "host key") {
		t.Fatalf("unexpected validation %v", e)
	}
	if e = remotePath("/safe/../escape/key", []string{"/safe"}); e == nil {
		t.Fatal("remote traversal accepted")
	}
}
func TestBTDeploymentProductsAndPartialResults(t *testing.T) {
	chain, key := deployFixture(t)
	for _, kind := range []string{"0", "1", "2", "3", "4"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				if r.Form.Get("request_token") != md5hex(r.Form.Get("request_time")+md5hex("fixture-secret")) {
					t.Error("BT signature mismatch")
				}
				calls++
				if kind == "1" {
					if r.URL.Query().Get("action") != "SavePanelSSL" || r.Form.Get("privateKey") != key {
						t.Error("panel certificate payload mismatch")
					}
				}
				if r.Form.Get("siteName") == "bad.example.com" {
					_, _ = w.Write([]byte(`{"status":false,"msg":"fixture failure"}`))
					return
				}
				_, _ = w.Write([]byte(`{"status":true}`))
			}))
			defer server.Close()
			p, e := New("btpanel", map[string]string{"url": server.URL, "key": "fixture-secret"}, Options{HTTPClient: server.Client()})
			if e != nil {
				t.Fatal(e)
			}
			target := Target{Config: map[string]string{"type": kind, "sites": "bad.example.com\nexample.com"}}
			info, e := p.Deploy(context.Background(), chain, key, target, nil)
			if kind == "0" {
				var partial *PartialError
				if !errors.As(e, &partial) || partial.Succeeded != 1 || partial.Failed != 1 || len(info["results"].([]ItemResult)) != 2 {
					t.Fatalf("bad partial result %v %v", info, e)
				}
			} else if e != nil {
				t.Fatal(e)
			}
			if calls == 0 {
				t.Fatal("no deployment calls")
			}
		})
	}
}
func TestNPMCheckpointAndMultipart(t *testing.T) {
	chain, key := deployFixture(t)
	created, uploaded, bound := 0, 0, 0
	persisted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respond := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		switch r.URL.Path {
		case "/api/tokens":
			respond(map[string]string{"token": "fixture-token"})
		case "/api/nginx/proxy-hosts":
			respond([]any{map[string]any{"id": 1, "domain_names": []string{"example.com"}}})
		case "/api/nginx/proxy-hosts/1":
			if r.Method == http.MethodPut {
				bound++
				respond(map[string]any{"id": 1})
				return
			}
			respond(map[string]any{"id": 1, "domain_names": []string{"example.com"}, "certificate_id": 0})
		case "/api/nginx/certificates":
			created++
			respond(map[string]int{"id": 9})
		case "/api/nginx/certificates/9":
			respond(map[string]any{"id": 9, "provider": "other"})
		case "/api/nginx/certificates/9/upload":
			if !persisted {
				t.Error("upload happened before ID checkpoint")
			}
			reader, e := r.MultipartReader()
			if e != nil {
				t.Error(e)
				return
			}
			fields := map[string]string{}
			for {
				part, e := reader.NextPart()
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Error(e)
					break
				}
				raw, _ := io.ReadAll(part)
				fields[part.FormName()] = string(raw)
			}
			if fields["certificate_key"] != key || !strings.Contains(fields["certificate"], "BEGIN CERTIFICATE") {
				t.Error("invalid NPM multipart")
			}
			uploaded++
			respond(map[string]bool{"ok": true})
		default:
			t.Errorf("unexpected NPM %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	opts := Options{HTTPClient: server.Client(), Checkpoint: func(_ context.Context, info Info) error {
		if text(info["certificate_id"]) != "9" {
			t.Error("bad checkpoint")
		}
		persisted = true
		return nil
	}}
	p, e := New("nginxproxymanager", map[string]string{"url": server.URL, "email": "fixture@example.com", "password": "fixture-password"}, opts)
	if e != nil {
		t.Fatal(e)
	}
	target := Target{Domains: []string{"example.com"}, Config: map[string]string{}}
	info, e := p.Deploy(context.Background(), chain, key, target, nil)
	if e != nil {
		t.Fatal(e)
	}
	if created != 1 || uploaded != 1 || bound != 1 {
		t.Fatalf("wrong NPM side effects %d %d %d", created, uploaded, bound)
	}
	if _, e = p.Deploy(context.Background(), chain, key, target, info); e != nil {
		t.Fatal(e)
	}
	if created != 1 {
		t.Fatal("resume created a second certificate")
	}
}
func TestUniCloudPasswordEnvelope(t *testing.T) {
	private, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	p := &unicloudProvider{httpProvider: &httpProvider{cfg: map[string]string{"username": "fixture@example.com", "password": "fixture-secret"}, opts: Options{Now: time.Now}}}
	data := map[string]any{"version": 1, "algorithm": "RSA-OAEP-256+A256GCM", "keyId": "key-1", "challengeId": "challenge-1", "publicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
	envelope, e := p.envelope(data)
	if e != nil {
		t.Fatal(e)
	}
	encryptedKey, _ := base64.StdEncoding.DecodeString(text(envelope["encryptedKey"]))
	key, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, private, encryptedKey, nil)
	if e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		t.Fatal(e)
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	iv, _ := base64.StdEncoding.DecodeString(text(envelope["iv"]))
	encrypted, _ := base64.StdEncoding.DecodeString(text(envelope["ciphertext"]))
	tag, _ := base64.StdEncoding.DecodeString(text(envelope["tag"]))
	aad := []byte(`{"version":1,"algorithm":"RSA-OAEP-256+A256GCM","keyId":"key-1","challengeId":"challenge-1"}`)
	raw, e := gcm.Open(nil, iv, append(encrypted, tag...), aad)
	if e != nil {
		t.Fatal(e)
	}
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	if text(payload["password"]) != "fixture-secret" || text(payload["email"]) != "fixture@example.com" {
		t.Fatal("encrypted credential payload mismatch")
	}
}
func TestWildcardAndRenewalIdentity(t *testing.T) {
	if domainMatches("*.example.com", "a.b.example.com") || domainMatches("*.example.com", "example.com") || !domainMatches("*.example.com", "www.example.com") {
		t.Fatal("wildcard label matching failed")
	}
	info := renewedInfo(Info{"fingerprint": "old", "cert_id": "old-id", "other": "keep"}, "new", "cert_id")
	if info["cert_id"] != nil || info["other"] != "keep" {
		t.Fatal("renewal retained obsolete certificate identity")
	}
}

func TestLocalWriteRejectsParentReplacement(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	parent := filepath.Join(root, "tls")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	destination, err := canonicalDestination(filepath.Join(parent, "key.pem"), []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(parent, filepath.Join(root, "renamed")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, parent); err != nil {
		t.Fatal(err)
	}
	if err = atomicWrite(destination, []byte("fixture-key"), 0600, []string{root}); err == nil {
		t.Fatal("parent replacement escaped OpenRoot")
	}
	if _, err = os.Stat(filepath.Join(outside, "key.pem")); !os.IsNotExist(err) {
		t.Fatal("private key was written outside allowed root")
	}
}

func TestDirectAdminJSONAndHTTPS(t *testing.T) {
	chain, key := deployFixture(t)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		user, pass, ok := r.BasicAuth()
		if !ok || user != "fixture-user" || pass != "fixture-pass" {
			t.Error("DirectAdmin authentication mismatch")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Method == http.MethodPost && !strings.Contains(r.Form.Get("certificate"), "BEGIN EC PRIVATE KEY") {
			t.Error("DirectAdmin EC SEC1 conversion absent")
		}
		io.WriteString(w, `{"error":false,"details":"success"}`)
	}))
	defer server.Close()
	cfg := map[string]string{"url": server.URL, "username": "fixture-user", "password": "fixture-pass"}
	p, err := New("directadmin", cfg, Options{HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Deploy(context.Background(), chain, key, Target{Config: map[string]string{"domain": "example.com"}}, nil); err != nil || requests != 2 {
		t.Fatalf("DirectAdmin err=%v requests=%d", err, requests)
	}
	cfg["url"] = strings.Replace(server.URL, "https:", "http:", 1)
	p, _ = New("directadmin", cfg, Options{})
	if _, err = p.Deploy(context.Background(), chain, key, Target{Config: map[string]string{"domain": "example.com"}}, nil); err == nil {
		t.Fatal("DirectAdmin deployed over plaintext HTTP")
	}
}

func TestFnOSWriterPinsDirectoryAndBoundsOutput(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	keyFile := filepath.Join(root, "key.pem")
	command, err := fnosWriteCommand(keyFile, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	// Execute the command's inner shell locally without sudo; all paths are isolated fixtures.
	inner := strings.TrimPrefix(command, "sudo -n ")
	cmd := exec.Command("/bin/sh", "-c", inner)
	cmd.Stdin = strings.NewReader("fixture-key")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fnOS isolated write err=%v output=%s", err, output)
	}
	info, err := os.Stat(keyFile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("fnOS private key mode mismatch")
	}
	if err = os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	command, err = fnosWriteCommand(filepath.Join(root, "escape", "escape.key"), []string{root})
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("/bin/sh", "-c", strings.TrimPrefix(command, "sudo -n "))
	cmd.Stdin = strings.NewReader("fixture-key")
	if err = cmd.Run(); err == nil {
		t.Fatal("fnOS physical parent escaped allowlist")
	}
	if _, err = os.Stat(filepath.Join(outside, "escape.key")); !os.IsNotExist(err) {
		t.Fatal("fnOS wrote outside root")
	}
	var buffer bytes.Buffer
	writer := &limitedOutput{buffer: &buffer, limit: 8}
	if _, err = writer.Write([]byte("123456789")); err == nil || buffer.Len() > 8 {
		t.Fatal("fnOS output allocation exceeded limit")
	}
}
