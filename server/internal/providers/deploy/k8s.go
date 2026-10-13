package deploy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go.yaml.in/yaml/v3"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type kubeConfig struct {
	Current  string `yaml:"current-context"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server string `yaml:"server"`
			CA     string `yaml:"certificate-authority-data"`
			Skip   bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token string `yaml:"token"`
			Cert  string `yaml:"client-certificate-data"`
			Key   string `yaml:"client-key-data"`
			Auth  struct {
				Config map[string]string `yaml:"config"`
			} `yaml:"auth-provider"`
			Exec any `yaml:"exec"`
		} `yaml:"user"`
	} `yaml:"users"`
}
type k8sProvider struct {
	*httpProvider
	token string
}

func newK8s(cfg map[string]string, opts Options) (Provider, error) {
	var kc kubeConfig
	if err := yaml.Unmarshal([]byte(cfg["kubeconfig"]), &kc); err != nil {
		return nil, errors.New("invalid Kubernetes kubeconfig")
	}
	clusterName, userName := "", ""
	for _, entry := range kc.Contexts {
		if entry.Name == kc.Current {
			clusterName = entry.Context.Cluster
			userName = entry.Context.User
		}
	}
	if clusterName == "" || userName == "" {
		return nil, errors.New("Kubernetes current-context is missing")
	}
	endpoint, ca := "", ""
	for _, entry := range kc.Clusters {
		if entry.Name == clusterName {
			endpoint = entry.Cluster.Server
			ca = entry.Cluster.CA
			if entry.Cluster.Skip {
				return nil, errors.New("Kubernetes requires verified TLS; remove insecure-skip-tls-verify and supply CA data")
			}
		}
	}
	token, cert, key := "", "", ""
	for _, entry := range kc.Users {
		if entry.Name == userName {
			token = entry.User.Token
			if token == "" {
				token = entry.User.Auth.Config["access-token"]
			}
			cert = entry.User.Cert
			key = entry.User.Key
			if entry.User.Exec != nil {
				return nil, errors.New("Kubernetes exec credential plugins are not executed; supply token or embedded client certificate")
			}
		}
	}
	endpointURL, endpointErr := url.Parse(endpoint)
	if endpointErr != nil || endpointURL.Scheme != "https" || endpointURL.User != nil || endpointURL.RawQuery != "" || endpointURL.Fragment != "" {
		return nil, errors.New("Kubernetes requires an HTTPS API origin")
	}
	if endpoint == "" || token == "" && (cert == "" || key == "") {
		return nil, errors.New("Kubernetes API server and embedded credentials are required")
	}
	if opts.HTTPClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if ca != "" {
			raw, e := base64.StdEncoding.DecodeString(ca)
			if e != nil {
				return nil, errors.New("invalid Kubernetes CA data")
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(raw) {
				return nil, errors.New("invalid Kubernetes CA certificate")
			}
			tlsConfig.RootCAs = roots
		}
		if cert != "" {
			crt, e := base64.StdEncoding.DecodeString(cert)
			if e != nil {
				return nil, e
			}
			priv, e := base64.StdEncoding.DecodeString(key)
			if e != nil {
				return nil, e
			}
			pair, e := tls.X509KeyPair(crt, priv)
			if e != nil {
				return nil, errors.New("invalid Kubernetes client certificate/key")
			}
			tlsConfig.Certificates = []tls.Certificate{pair}
		}
		transport.TLSClientConfig = tlsConfig
		opts.HTTPClient = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	}
	copy := map[string]string{}
	for k, v := range cfg {
		copy[k] = v
	}
	copy["url"] = endpoint
	p, e := newHTTP("k8s", copy, opts)
	if e != nil {
		return nil, e
	}
	return &k8sProvider{p, token}, nil
}
func (p *k8sProvider) call(ctx context.Context, method, path string, body any) (map[string]any, int, error) {
	var raw []byte
	if body != nil {
		var e error
		raw, e = json.Marshal(body)
		if e != nil {
			return nil, 0, e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, p.base+path, bytes.NewReader(raw))
	if e != nil {
		return nil, 0, e
	}
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		if method == http.MethodPatch {
			req.Header.Set("Content-Type", "application/merge-patch+json")
		}
	}
	resp, e := p.client.Do(req)
	if e != nil {
		return nil, 0, e
	}
	defer resp.Body.Close()
	raw, e = readLimited(resp.Body)
	if e != nil {
		return nil, resp.StatusCode, e
	}
	var value map[string]any
	if len(raw) > 0 && json.Unmarshal(raw, &value) != nil {
		return nil, resp.StatusCode, errors.New("invalid Kubernetes JSON")
	}
	if resp.StatusCode/100 != 2 && !(resp.StatusCode == 404 && method == http.MethodGet) {
		return nil, resp.StatusCode, rejectedHTTP("k8s", resp.StatusCode, "provider request failed")
	}
	return value, resp.StatusCode, nil
}
func (p *k8sProvider) Validate(ctx context.Context) error {
	_, status, e := p.call(ctx, http.MethodGet, "/version", nil)
	if e == nil && status != 200 {
		e = errors.New("Kubernetes version endpoint unavailable")
	}
	return e
}
func (p *k8sProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	namespace, secret := target.Config["namespace"], target.Config["secret_name"]
	valid := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`)
	namespaceValid := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	if len(namespace) > 63 || len(secret) > 253 || !namespaceValid.MatchString(namespace) || !valid.MatchString(secret) {
		return info, errors.New("valid Kubernetes namespace and Secret names are required")
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/secrets/" + url.PathEscape(secret)
	existing, status, e := p.call(ctx, http.MethodGet, path, nil)
	if e != nil {
		return info, e
	}
	payload := map[string]any{"data": map[string]string{"tls.crt": base64.StdEncoding.EncodeToString([]byte(chain)), "tls.key": base64.StdEncoding.EncodeToString([]byte(key))}, "type": "kubernetes.io/tls"}
	if status == 404 {
		payload["apiVersion"] = "v1"
		payload["kind"] = "Secret"
		payload["metadata"] = map[string]string{"name": secret, "namespace": namespace}
		_, _, e = p.call(ctx, http.MethodPost, strings.TrimSuffix(path, "/"+url.PathEscape(secret)), payload)
	} else {
		payload["metadata"] = map[string]any{"resourceVersion": obj(existing["metadata"])["resourceVersion"]}
		_, _, e = p.call(ctx, http.MethodPatch, path, payload)
	}
	if e != nil {
		return info, e
	}
	info["secret_name"] = secret
	info["namespace"] = namespace
	info["fingerprint"] = sha256hex(leaf.Raw)
	ingresses := splitLines(strings.ReplaceAll(target.Config["ingresses"], ",", "\n"))
	if len(ingresses) == 0 {
		return info, nil
	}
	return batch(ctx, ingresses, info, func(name string) error {
		if len(name) > 253 || !valid.MatchString(name) {
			return errors.New("invalid Ingress name")
		}
		path := "/apis/networking.k8s.io/v1/namespaces/" + url.PathEscape(namespace) + "/ingresses/" + url.PathEscape(name)
		ingress, status, e := p.call(ctx, http.MethodGet, path, nil)
		if e != nil {
			return e
		}
		if status == 404 {
			return errors.New("Ingress not found")
		}
		spec := obj(ingress["spec"])
		hosts := []string{}
		for _, rule := range anyList(spec["rules"]) {
			host := text(obj(rule)["host"])
			if host == "" {
				continue
			}
			if err := leaf.VerifyHostname(host); err != nil {
				return errors.New("certificate does not cover Ingress host")
			}
			hosts = append(hosts, host)
		}
		entries := anyList(spec["tls"])
		found := false
		for _, entry := range entries {
			m := obj(entry)
			if text(m["secretName"]) != secret {
				continue
			}
			found = true
			all := append(stringList(m["hosts"]), hosts...)
			seen := map[string]bool{}
			unique := []string{}
			for _, host := range all {
				if !seen[host] {
					unique = append(unique, host)
					seen[host] = true
				}
			}
			m["hosts"] = unique
		}
		if !found {
			entries = append(entries, map[string]any{"secretName": secret, "hosts": hosts})
		}
		_, _, e = p.call(ctx, http.MethodPatch, path, map[string]any{"metadata": map[string]any{"resourceVersion": obj(ingress["metadata"])["resourceVersion"]}, "spec": map[string]any{"tls": entries}})
		return e
	})
}
