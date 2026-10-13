package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Calculate the signature from the received wire request, independently of signAWS.
func verifySigV4(t *testing.T, r *http.Request, raw []byte, secret string) {
	t.Helper()
	auth := r.Header.Get("Authorization")
	fields := strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ", ")
	values := map[string]string{}
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if ok {
			values[k] = v
		}
	}
	credentials := strings.Split(values["Credential"], "/")
	if len(credentials) != 5 {
		t.Fatalf("invalid AWS credential scope: %s", auth)
	}
	headerNames := strings.Split(values["SignedHeaders"], ";")
	canonicalHeaders := ""
	for _, name := range headerNames {
		v := r.Header.Get(name)
		if name == "host" {
			v = r.Host
		}
		canonicalHeaders += name + ":" + strings.Join(strings.Fields(v), " ") + "\n"
	}
	hash := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
	query := r.URL.Query()
	keys := []string{}
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{}
	for _, k := range keys {
		values := query[k]
		sort.Strings(values)
		for _, v := range values {
			parts = append(parts, strings.ReplaceAll(url.QueryEscape(k), "+", "%20")+"="+strings.ReplaceAll(url.QueryEscape(v), "+", "%20"))
		}
	}
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + strings.Join(parts, "&") + "\n" + canonicalHeaders + "\n" + values["SignedHeaders"] + "\n" + hash(raw)
	scope := strings.Join(credentials[1:], "/")
	toSign := "AWS4-HMAC-SHA256\n" + r.Header.Get("X-Amz-Date") + "\n" + scope + "\n" + hash([]byte(canonical))
	mac := func(key []byte, value string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(value))
		return h.Sum(nil)
	}
	signingKey := []byte("AWS4" + secret)
	for _, part := range credentials[1:] {
		signingKey = mac(signingKey, part)
	}
	if hex.EncodeToString(mac(signingKey, toSign)) != values["Signature"] {
		t.Error("AWS wire signature mismatch")
	}
}

func TestAWSCloudFrontPreservesConfiguration(t *testing.T) {
	chain, key := deployFixture(t)
	imported, saved, bound := 0, false, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		verifySigV4(t, r, raw, "fixture-secret")
		switch {
		case r.Header.Get("X-Amz-Target") == "CertificateManager.ImportCertificate":
			imported++
			var body map[string]any
			json.Unmarshal(raw, &body)
			crt, _ := base64.StdEncoding.DecodeString(text(body["Certificate"]))
			priv, _ := base64.StdEncoding.DecodeString(text(body["PrivateKey"]))
			if string(crt) != chain || string(priv) != key {
				t.Error("ACM PEM payload mismatch")
			}
			io.WriteString(w, `{"CertificateArn":"arn:fixture:new"}`)
		case r.Method == "GET":
			if !saved {
				t.Error("CloudFront queried before ARN checkpoint")
			}
			w.Header().Set("ETag", "fixture-etag")
			io.WriteString(w, `<DistributionConfig xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><CallerReference>keep-caller</CallerReference><Origins><Quantity>1</Quantity><Items><Origin><Id>keep-origin</Id><DomainName>origin.example.com</DomainName></Origin></Items></Origins><Enabled>true</Enabled><ViewerCertificate><CloudFrontDefaultCertificate>true</CloudFrontDefaultCertificate><MinimumProtocolVersion>TLSv1.2_2021</MinimumProtocolVersion></ViewerCertificate></DistributionConfig>`)
		case r.Method == "PUT":
			bound = true
			if r.Header.Get("If-Match") != "fixture-etag" {
				t.Error("CloudFront optimistic lock omitted")
			}
			node, err := parseXMLTree(raw)
			if err != nil {
				t.Fatal(err)
			}
			if node.child("CallerReference").Text != "keep-caller" || node.child("Origins").child("Items").child("Origin").child("Id").Text != "keep-origin" {
				t.Error("CloudFront unrelated fields lost")
			}
			if node.child("ViewerCertificate").child("ACMCertificateArn").Text != "arn:fixture:new" {
				t.Error("CloudFront certificate not bound")
			}
		default:
			t.Errorf("unexpected AWS request %s", r.URL)
		}
	}))
	defer srv.Close()
	p, err := New("aws", map[string]string{"url": srv.URL, "AccessKeyId": "fixture-access", "SecretAccessKey": "fixture-secret"}, Options{Checkpoint: func(_ context.Context, info Info) error {
		saved = text(info["cert_id"]) == "arn:fixture:new"
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Deploy(context.Background(), chain, key, Target{Config: map[string]string{"product": "cloudfront", "distribution_id": "dist-fixture"}}, nil)
	if err != nil || imported != 1 || !bound {
		t.Fatalf("AWS err=%v imports=%d bound=%v", err, imported, bound)
	}
	saved, bound = false, false
	p, _ = New("aws", map[string]string{"url": srv.URL, "AccessKeyId": "fixture-access", "SecretAccessKey": "fixture-secret"}, Options{Checkpoint: func(context.Context, Info) error { return errors.New("fixture database unavailable") }})
	if _, err = p.Deploy(context.Background(), chain, key, Target{Config: map[string]string{"product": "cloudfront", "distribution_id": "dist-fixture"}}, nil); err == nil || bound {
		t.Fatal("AWS continued after checkpoint failure")
	}
}

func TestS3EscapesObjectKeysAndPreservesSignature(t *testing.T) {
	chain, key := deployFixture(t)
	paths := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		verifySigV4(t, r, raw, "fixture-secret")
		paths = append(paths, r.URL.Path)
		if r.URL.RawQuery != "" || r.URL.Fragment != "" {
			t.Error("S3 object key escaped into URL query")
		}
	}))
	defer srv.Close()
	p, err := New("s3storage", map[string]string{"url": srv.URL, "AccessKeyId": "fixture-access", "SecretAccessKey": "fixture-secret"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Deploy(context.Background(), chain, key, Target{Config: map[string]string{"bucket": "fixture", "cert_path": "tls/my cert?.pem", "key_path": "tls/private#key.pem"}}, nil)
	if err != nil || len(paths) != 2 || paths[0] != "/fixture/tls/my cert?.pem" || paths[1] != "/fixture/tls/private#key.pem" {
		t.Fatalf("S3 paths=%v err=%v", paths, err)
	}
}

func TestTencentUpdateResumeRenewalAndSafeDeletion(t *testing.T) {
	chain, key := deployFixture(t)
	newChain, newKey := deployFixture(t)
	currentChain := chain
	expectedOld := "old-id"
	updates, deleted := 0, []string{}
	checkpointRecord := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		// Independently reproduce TC3 canonical request using wire headers/body.
		timestamp := r.Header.Get("X-TC-Timestamp")
		seconds, _ := strconv.ParseInt(timestamp, 10, 64)
		date := time.Unix(seconds, 0).UTC().Format("2006-01-02")
		digest := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
		mac := func(key []byte, v string) []byte {
			h := hmac.New(sha256.New, key)
			h.Write([]byte(v))
			return h.Sum(nil)
		}
		canonical := "POST\n/\n\ncontent-type:" + r.Header.Get("Content-Type") + "\nhost:" + r.Host + "\n\ncontent-type;host\n" + digest(raw)
		scope := date + "/ssl/tc3_request"
		signing := mac(mac(mac([]byte("TC3fixture-secret"), date), "ssl"), "tc3_request")
		signature := hex.EncodeToString(mac(signing, "TC3-HMAC-SHA256\n"+timestamp+"\n"+scope+"\n"+digest([]byte(canonical))))
		if !strings.HasSuffix(r.Header.Get("Authorization"), "Signature="+signature) {
			t.Error("Tencent TC3 wire signature mismatch")
		}
		out := map[string]any{}
		switch r.Header.Get("X-TC-Action") {
		case "CreateCertificateBindResourceSyncTask":
			if text(anyList(body["CertificateIds"])[0]) != expectedOld {
				t.Errorf("renewal queried old=%v want=%s", body, expectedOld)
			}
			out["CertTaskIds"] = []any{map[string]any{"TaskId": "sync-id"}}
		case "DescribeCertificateBindResourceTaskResult":
			out["SyncTaskBindResourceResult"] = []any{map[string]any{"Status": 1, "BindResourceResult": []any{map[string]any{"ResourceType": "cdn", "BindResourceRegionResult": []any{map[string]any{"TotalCount": 1, "Region": "global"}}}}}}
		case "UpdateCertificateInstance":
			updates++
			if text(body["OldCertificateId"]) != expectedOld {
				t.Error("Tencent update targeted wrong old certificate")
			}
			if _, ok := body["ResourceTypesRegions"]; ok {
				t.Error("Tencent CDN incorrectly included regional resources")
			}
			out["DeployRecordId"] = 9007199254740993
			out["DeployStatus"] = 1
		case "DescribeHostDeployRecordDetail":
			if !checkpointRecord {
				t.Error("Tencent polled before task checkpoint")
			}
			if text(body["DeployRecordId"]) != "9007199254740993" {
				t.Error("Tencent task ID lost integer precision")
			}
			out = map[string]any{"RunningTotalCount": 0, "PendingTotalCount": 0, "SuccessTotalCount": 1, "FailedTotalCount": 0, "TotalCount": 1, "DeployRecordDetailList": []any{map[string]any{"InstanceId": "example.com", "CertId": fmt.Sprintf("new-id-%d", updates), "Status": 1}}}
		case "DescribeCertificateDetail":
			out["CertificatePublicKey"] = currentChain
		case "DeleteCertificate":
			if !checkpointRecord {
				t.Error("Tencent deleted before deployment checkpoint")
			}
			deleted = append(deleted, text(body["CertificateId"]))
		default:
			t.Errorf("unexpected Tencent action %s", r.Header.Get("X-TC-Action"))
		}
		json.NewEncoder(w).Encode(map[string]any{"Response": out})
	}))
	defer srv.Close()
	cfg := map[string]string{"url": srv.URL, "SecretId": "fixture-access", "SecretKey": "fixture-secret"}
	target := Target{Config: map[string]string{"product": "update_new", "cert_id": "old-id", "delete_old_cert": "1"}}
	var saved Info
	p, _ := New("tencent", cfg, Options{Checkpoint: func(_ context.Context, info Info) error {
		saved = cloneInfo(info)
		if text(info["update_record_id"]) != "" {
			checkpointRecord = true
		}
		return nil
	}})
	info, err := p.Deploy(context.Background(), chain, key, target, nil)
	if err != nil || updates != 1 || len(deleted) != 1 || deleted[0] != "old-id" {
		t.Fatalf("Tencent err=%v updates=%d deleted=%v", err, updates, deleted)
	}
	if !truth(saved["old_cert_deleted"]) {
		t.Error("Tencent deletion completion not persisted")
	}
	_, err = p.Deploy(context.Background(), chain, key, target, info)
	if err != nil || updates != 1 || len(deleted) != 1 {
		t.Fatal("Tencent resume repeated mutation")
	}
	currentChain = newChain
	expectedOld = "new-id-1"
	checkpointRecord = false
	_, err = p.Deploy(context.Background(), newChain, newKey, target, info)
	if err != nil || updates != 2 || len(deleted) != 2 || deleted[1] != "new-id-1" {
		t.Fatalf("Tencent renewal err=%v updates=%d deleted=%v", err, updates, deleted)
	}
}

func TestKubernetesVerifiedTLSCreatePatchAndIngressMerge(t *testing.T) {
	chain, key := deployFixture(t)
	for _, mtls := range []bool{false, true} {
		t.Run(fmt.Sprint(mtls), func(t *testing.T) {
			exists := false
			created, patched, ingressPatches := 0, 0, 0
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mtls {
					if len(r.TLS.PeerCertificates) != 1 {
						t.Error("Kubernetes client certificate missing")
					}
				} else if r.Header.Get("Authorization") != "Bearer fixture-token" {
					t.Error("Kubernetes bearer token missing")
				}
				var body map[string]any
				json.NewDecoder(r.Body).Decode(&body)
				switch {
				case r.Method == "GET" && strings.Contains(r.URL.Path, "secrets/"):
					if !exists {
						w.WriteHeader(404)
						io.WriteString(w, `{"reason":"NotFound"}`)
						return
					}
					io.WriteString(w, `{"metadata":{"resourceVersion":"7","labels":{"preserve":"yes"}}}`)
				case r.Method == "POST":
					created++
					exists = true
					io.WriteString(w, `{}`)
				case r.Method == "PATCH" && strings.Contains(r.URL.Path, "secrets/"):
					patched++
					if r.Header.Get("Content-Type") != "application/merge-patch+json" || text(obj(body["metadata"])["resourceVersion"]) != "7" {
						t.Error("Secret patch missing concurrency guard")
					}
					if len(obj(body["metadata"])) != 1 {
						t.Error("Secret patch replaced labels")
					}
					io.WriteString(w, `{}`)
				case r.Method == "GET" && strings.Contains(r.URL.Path, "ingresses/"):
					io.WriteString(w, `{"metadata":{"resourceVersion":"8"},"spec":{"rules":[{"host":"www.example.com"}],"tls":[{"secretName":"other-secret","hosts":["other.example.com"]}]}}`)
				case r.Method == "PATCH" && strings.Contains(r.URL.Path, "ingresses/"):
					ingressPatches++
					spec := obj(body["spec"])
					if len(spec) != 1 || len(anyList(spec["tls"])) != 2 || text(obj(anyList(spec["tls"])[0])["secretName"]) != "other-secret" {
						t.Error("Ingress TLS merge lost existing configuration")
					}
					io.WriteString(w, `{}`)
				default:
					t.Errorf("unexpected Kubernetes request %s %s", r.Method, r.URL)
				}
			}))
			if mtls {
				roots := x509.NewCertPool()
				roots.AppendCertsFromPEM([]byte(chain))
				srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
			}
			srv.StartTLS()
			defer srv.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
			user := "token: fixture-token"
			if mtls {
				user = "client-certificate-data: " + base64.StdEncoding.EncodeToString([]byte(chain)) + "\n      client-key-data: " + base64.StdEncoding.EncodeToString([]byte(key))
			}
			kube := fmt.Sprintf("current-context: fixture\ncontexts:\n- name: fixture\n  context: {cluster: fixture, user: fixture}\nclusters:\n- name: fixture\n  cluster:\n    server: %s\n    certificate-authority-data: %s\nusers:\n- name: fixture\n  user:\n      %s\n", srv.URL, base64.StdEncoding.EncodeToString(ca), user)
			p, err := New("k8s", map[string]string{"kubeconfig": kube}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			target := Target{Config: map[string]string{"namespace": "default", "secret_name": "tls-fixture", "ingresses": "app"}}
			for i := 0; i < 2; i++ {
				if _, err = p.Deploy(context.Background(), chain, key, target, nil); err != nil {
					t.Fatal(err)
				}
			}
			if created != 1 || patched != 1 || ingressPatches != 2 {
				t.Fatalf("Kubernetes creates=%d patches=%d ingress=%d", created, patched, ingressPatches)
			}
		})
	}
}

func TestTencentFailureNeverDeletesOldCertificate(t *testing.T) {
	chain, key := deployFixture(t)
	leaf, _, _, _ := parsePair(chain, key)
	deletes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-TC-Action") == "DeleteCertificate" {
			deletes++
		}
		json.NewEncoder(w).Encode(map[string]any{"Response": map[string]any{"RunningTotalCount": 0, "PendingTotalCount": 0, "SuccessTotalCount": 1, "FailedTotalCount": 1, "DeployRecordDetailList": []any{map[string]any{"InstanceId": "good", "Status": 1}, map[string]any{"InstanceId": "bad", "Status": 2, "ErrorMsg": "fixture failed"}}}})
	}))
	defer srv.Close()
	target := Target{Config: map[string]string{"product": "update_new", "cert_id": "old", "delete_old_cert": "1"}}
	identity := sha256hex([]byte("update_new\nold"))
	prior := Info{"update_fingerprint": sha256hex(leaf.Raw), "update_target_identity": identity, "update_old_cert_id": "old", "update_record_id": "record"}
	p, _ := New("tencent", map[string]string{"url": srv.URL, "SecretId": "fixture", "SecretKey": "fixture"}, Options{Checkpoint: func(context.Context, Info) error { return nil }})
	_, err := p.Deploy(context.Background(), chain, key, target, prior)
	var partial *PartialError
	if !errors.As(err, &partial) || deletes != 0 {
		t.Fatalf("Tencent partial=%v deletes=%d", err, deletes)
	}
}
