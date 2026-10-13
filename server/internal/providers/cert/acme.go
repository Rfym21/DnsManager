package cert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"golang.org/x/net/idna"
)

type acmeProvider struct {
	kind      string
	cfg       map[string]string
	opts      Options
	directory string
}

func New(kind string, cfg map[string]string, opts Options) (Provider, error) {
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 40 * time.Second}
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 3 * time.Second
	}
	var directory string
	switch kind {
	case "letsencrypt":
		directory = "https://acme-v02.api.letsencrypt.org/directory"
		if cfg["mode"] == "staging" {
			directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
		}
	case "zerossl":
		directory = "https://acme.zerossl.com/v2/DV90"
	case "google":
		directory = "https://dv.acme-v02.api.pki.goog/directory"
		if cfg["mode"] == "staging" {
			directory = "https://dv.acme-v02.test-api.pki.goog/directory"
		}
	case "litessl":
		directory = "https://acme.litessl.com/acme/v2/directory"
	case "customacme":
		directory = cfg["directory"]
	case "tencent", "aliyun", "ucloud", "huoshan":
		return newCloud(kind, cfg, opts)
	default:
		return nil, fmt.Errorf("unknown certificate provider %q", kind)
	}
	if opts.Endpoint != "" {
		directory = opts.Endpoint
	}
	if kind == "google" && cfg["proxy"] == "2" {
		proxy, e := url.Parse(strings.TrimRight(cfg["proxy_url"], "/"))
		origin, e2 := url.Parse(directory)
		if e != nil || e2 != nil || proxy.Host == "" || (proxy.Scheme != "https" && proxy.Scheme != "http") || proxy.User != nil {
			return nil, errors.New("valid Google reverse proxy URL is required")
		}
		client := *opts.HTTPClient
		base := client.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		client.Transport = reverseProxyTransport{base: base, origin: origin, proxy: proxy}
		opts.HTTPClient = &client
	}
	u, err := url.Parse(directory)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("invalid ACME directory URL")
	}
	return &acmeProvider{kind: kind, cfg: cfg, opts: opts, directory: directory}, nil
}

type contextTransport struct {
	ctx  context.Context
	base http.RoundTripper
}
type reverseProxyTransport struct {
	base          http.RoundTripper
	origin, proxy *url.URL
}

func (t reverseProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != t.origin.Scheme || req.URL.Host != t.origin.Host {
		return t.base.RoundTrip(req)
	}
	clone := req.Clone(req.Context())
	u := *req.URL
	u.Scheme = t.proxy.Scheme
	u.Host = t.proxy.Host
	u.Path = strings.TrimRight(t.proxy.Path, "/") + req.URL.Path
	clone.URL = &u
	clone.Host = t.proxy.Host
	return t.base.RoundTrip(clone)
}

func (t contextTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(req.Clone(t.ctx))
}
func boundClient(ctx context.Context, original *http.Client) *http.Client {
	c := *original
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.Transport = contextTransport{ctx: ctx, base: base}
	return &c
}
func (p *acmeProvider) core(ctx context.Context, state AccountState) (*api.Core, error) {
	key, err := ParsePrivateKey(state.KeyPEM)
	if err != nil {
		return nil, err
	}
	return api.New(boundClient(ctx, p.opts.HTTPClient), "DNS-Manager-Go", p.directory, state.URL, key)
}
func (p *acmeProvider) Register(ctx context.Context, state AccountState) (AccountState, error) {
	if _, err := mail.ParseAddress(p.cfg["email"]); err != nil {
		return state, errors.New("valid account email is required")
	}
	if state.Directory != "" && state.Directory != p.directory {
		return state, errors.New("account directory differs; create a separate staging/live account")
	}
	state.Directory = p.directory
	state.Email = p.cfg["email"]
	if state.KeyPEM == "" {
		key, err := generateKey("RSA", 2048)
		if err != nil {
			return state, err
		}
		state.KeyPEM = key
	}
	core, err := p.core(ctx, state)
	if err != nil {
		return state, err
	}
	if state.URL != "" {
		account, e := core.Accounts.Get(state.URL)
		if e != nil {
			return state, e
		}
		if account.Status != acme.StatusValid {
			return state, fmt.Errorf("ACME account is %s", account.Status)
		}
		return state, nil
	}
	kid, key, err := p.eab(ctx)
	if err != nil {
		return state, err
	}
	message := acme.Account{Contact: []string{"mailto:" + state.Email}, TermsOfServiceAgreed: true}
	var registered acme.ExtendedAccount
	if kid != "" {
		registered, err = core.Accounts.NewEAB(message, kid, key)
	} else {
		registered, err = core.Accounts.New(message)
	}
	if err != nil {
		return state, err
	}
	state.URL = registered.Location
	return state, nil
}
func (p *acmeProvider) eab(ctx context.Context) (string, string, error) {
	kid, key := p.cfg["kid"], p.cfg["key"]
	if p.cfg["eabMode"] == "auto" && (p.kind == "google" || p.kind == "zerossl") {
		endpoint, method := "https://gts.rat.dev/eab", http.MethodGet
		var body io.Reader
		if p.kind == "zerossl" {
			endpoint = "https://api.zerossl.com/acme/eab-credentials-email"
			method = http.MethodPost
			body = strings.NewReader(url.Values{"email": {p.cfg["email"]}}.Encode())
		}
		if p.cfg["eab_url"] != "" {
			endpoint = p.cfg["eab_url"]
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
		if err != nil {
			return "", "", err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		res, err := p.opts.HTTPClient.Do(req)
		if err != nil {
			return "", "", err
		}
		defer res.Body.Close()
		var payload map[string]any
		if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&payload); err != nil {
			return "", "", errors.New("invalid EAB response")
		}
		if res.StatusCode/100 != 2 {
			return "", "", fmt.Errorf("EAB endpoint returned HTTP %d", res.StatusCode)
		}
		if p.kind == "google" {
			if payload["msg"] != "success" {
				return "", "", errors.New("Google EAB acquisition failed")
			}
			data, _ := payload["data"].(map[string]any)
			kid, _ = data["key_id"].(string)
			key, _ = data["mac_key"].(string)
		} else {
			kid, _ = payload["eab_kid"].(string)
			key, _ = payload["eab_hmac_key"].(string)
		}
	}
	if p.kind != "letsencrypt" && p.kind != "customacme" && (kid == "" || key == "") {
		return "", "", errors.New("EAB KID and HMAC key are required")
	}
	if (kid == "") != (key == "") {
		return "", "", errors.New("EAB KID and HMAC key must be supplied together")
	}
	return kid, key, nil
}
func (p *acmeProvider) Issue(ctx context.Context, request Request, cp *Checkpoint, dns DNSCallback, save SaveCheckpoint) (*Result, error) {
	if cp == nil || save == nil || dns == nil {
		return nil, errors.New("checkpoint, persistence and DNS callbacks are required")
	}
	domains, err := validateDomains(request.Domains, 100, true)
	if err != nil {
		return nil, err
	}
	if err = checkpointRequest(cp, request, domains); err != nil {
		return nil, err
	}
	if cp.Provider != "" && cp.Provider != p.kind {
		return nil, errors.New("checkpoint belongs to another provider")
	}
	cp.Version = 1
	cp.Provider = p.kind
	if cp.Account.KeyPEM == "" {
		cp.Account.KeyPEM, err = generateKey("RSA", 2048)
		if err != nil {
			return nil, err
		}
		cp.Account.Directory = p.directory
		cp.Account.Email = p.cfg["email"]
		if err = save(ctx, *cp); err != nil {
			return nil, err
		}
	}
	state, err := p.Register(ctx, cp.Account)
	if err != nil {
		return nil, err
	}
	cp.Account = state
	if err = save(ctx, *cp); err != nil {
		return nil, err
	}
	core, err := p.core(ctx, state)
	if err != nil {
		return nil, err
	}
	if cp.PrivateKey == "" {
		cp.PrivateKey, err = generateKey(request.KeyType, request.KeySize)
		if err != nil {
			return nil, err
		}
		if err = save(ctx, *cp); err != nil {
			return nil, err
		}
	}
	var order acme.ExtendedOrder
	if cp.OrderURL == "" {
		if cp.Stage == "creating_order" {
			return nil, &UnknownError{Message: "ACME订单曾提交但未保存URL，请核对CA账户订单后处理"}
		}
		cp.Stage = "creating_order"
		if err = save(ctx, *cp); err != nil {
			return nil, err
		}
		order, err = core.Orders.New(domains)
		if err != nil {
			return nil, &UnknownError{Message: "ACME订单提交结果未确认，请核对CA账户订单后处理"}
		}
		cp.OrderURL = order.Location
		cp.FinalizeURL = order.Finalize
		cp.Stage = "pending"
		if err = save(ctx, *cp); err != nil {
			return nil, err
		}
	} else {
		order, err = core.Orders.Get(cp.OrderURL)
		if err != nil {
			return nil, err
		}
	}
	if order.Status == acme.StatusInvalid {
		return nil, fmt.Errorf("ACME order invalid: %w", order.Err())
	}
	if len(cp.Challenges) == 0 && order.Status == acme.StatusPending {
		for _, authURL := range order.Authorizations {
			auth, e := core.Authorizations.Get(authURL)
			if e != nil {
				return nil, e
			}
			if auth.Status == acme.StatusValid {
				continue
			}
			found := false
			for _, challenge := range auth.Challenges {
				if challenge.Type != "dns-01" {
					continue
				}
				keyAuth, e := core.GetKeyAuthorization(challenge.Token)
				if e != nil {
					return nil, e
				}
				digest := sha256.Sum256([]byte(keyAuth))
				domain := auth.Identifier.Value
				cp.Challenges = append(cp.Challenges, Challenge{Domain: domain, Name: "_acme-challenge." + strings.TrimPrefix(domain, "*."), Type: "TXT", Value: base64.RawURLEncoding.EncodeToString(digest[:]), URL: challenge.URL, AuthorizationURL: authURL})
				found = true
				break
			}
			if !found {
				return nil, fmt.Errorf("DNS challenge unavailable for %s", auth.Identifier.Value)
			}
		}
		if err = save(ctx, *cp); err != nil {
			return nil, err
		}
	}
	for i := range cp.Challenges {
		ch := &cp.Challenges[i]
		if ch.Validated {
			continue
		}
		if !ch.Presented {
			receipt, e := dns.Present(ctx, *ch)
			if e != nil {
				return nil, e
			}
			ch.Receipt = receipt
			ch.Presented = true
			cp.Stage = "waiting_dns"
			if e = save(ctx, *cp); e != nil {
				return nil, e
			}
		}
	}
	for i := range cp.Challenges {
		ch := &cp.Challenges[i]
		if ch.Validated {
			continue
		}
		if err = dns.Wait(ctx, *ch); err != nil {
			return nil, err
		}
		auth, e := core.Authorizations.Get(ch.AuthorizationURL)
		if e != nil {
			return nil, e
		}
		if auth.Status != acme.StatusValid {
			if _, e = core.Challenges.New(ch.URL); e != nil {
				return nil, e
			}
			for {
				auth, e = core.Authorizations.Get(ch.AuthorizationURL)
				if e != nil {
					return nil, e
				}
				if auth.Status == acme.StatusValid {
					break
				}
				if auth.Status == acme.StatusInvalid || auth.Status == acme.StatusExpired || auth.Status == acme.StatusDeactivated {
					return nil, fmt.Errorf("ACME authorization became %s", auth.Status)
				}
				if e = wait(ctx, p.opts.PollInterval); e != nil {
					return nil, e
				}
			}
		}
		ch.Validated = true
		cp.Stage = "validated"
		if err = save(ctx, *cp); err != nil {
			return nil, err
		}
	}
	for {
		order, err = core.Orders.Get(cp.OrderURL)
		if err != nil {
			return nil, err
		}
		if order.Status == acme.StatusReady || order.Status == acme.StatusValid {
			break
		}
		if order.Status == acme.StatusInvalid {
			return nil, fmt.Errorf("ACME order invalid: %w", order.Err())
		}
		if order.Status == acme.StatusProcessing {
			break
		}
		if err = wait(ctx, p.opts.PollInterval); err != nil {
			return nil, err
		}
	}
	if order.Status == acme.StatusReady {
		key, e := ParsePrivateKey(cp.PrivateKey)
		if e != nil {
			return nil, e
		}
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains}, key)
		if e != nil {
			return nil, e
		}
		cp.Stage = "finalizing"
		if err = save(ctx, *cp); err != nil {
			return nil, err
		}
		order, err = core.Orders.UpdateForCSR(cp.FinalizeURL, csr)
		if err != nil {
			return nil, err
		}
	}
	for order.Status != acme.StatusValid {
		if order.Status == acme.StatusInvalid {
			return nil, fmt.Errorf("ACME finalize invalid: %w", order.Err())
		}
		if err = wait(ctx, p.opts.PollInterval); err != nil {
			return nil, err
		}
		order, err = core.Orders.Get(cp.OrderURL)
		if err != nil {
			return nil, err
		}
	}
	cp.CertificateURL = order.Certificate
	cp.Stage = "issued"
	if err = save(ctx, *cp); err != nil {
		return nil, err
	}
	chain, _, err := core.Certificates.Get(order.Certificate, true)
	if err != nil {
		return nil, err
	}
	if request.PreferredChain != "" {
		all, e := core.Certificates.GetAll(order.Certificate, true)
		if e != nil {
			return nil, e
		}
		urls := []string{}
		for u := range all {
			urls = append(urls, u)
		}
		sort.Strings(urls)
		found := false
		for _, u := range urls {
			candidate := all[u].Cert
			if chainIssuer(candidate, request.PreferredChain) {
				chain = candidate
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("requested preferred certificate chain is unavailable")
		}
	}
	result, err := ParseResult(string(chain), cp.PrivateKey)
	if err != nil {
		return nil, err
	}
	if err = verifyResultDomains(result, domains); err != nil {
		return nil, err
	}
	for i := range cp.Challenges {
		ch := &cp.Challenges[i]
		if !ch.Presented || ch.Cleaned {
			continue
		}
		if err = dns.Cleanup(ctx, *ch); err != nil {
			return result, fmt.Errorf("certificate issued; DNS cleanup requires retry: %w", err)
		}
		ch.Cleaned = true
		if err = save(ctx, *cp); err != nil {
			return result, err
		}
	}
	cp.Stage = "complete"
	return result, save(ctx, *cp)
}
func (p *acmeProvider) Revoke(ctx context.Context, cp *Checkpoint, chain string) error {
	if cp == nil {
		return errors.New("certificate checkpoint is required")
	}
	core, err := p.core(ctx, cp.Account)
	if err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(chain))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("certificate PEM is required")
	}
	return core.Certificates.Revoke(acme.RevokeCertMessage{Certificate: base64.RawURLEncoding.EncodeToString(block.Bytes)})
}
func (p *acmeProvider) Cancel(ctx context.Context, cp *Checkpoint) error {
	if cp == nil {
		return errors.New("certificate checkpoint is required")
	}
	core, err := p.core(ctx, cp.Account)
	if err != nil {
		return err
	}
	for _, ch := range cp.Challenges {
		if ch.AuthorizationURL != "" && !ch.Validated {
			if err = core.Authorizations.Deactivate(ch.AuthorizationURL); err != nil {
				return err
			}
		}
	}
	return cleanupCheckpoint(ctx, cp, p.opts)
}
func cleanupCheckpoint(ctx context.Context, cp *Checkpoint, opts Options) error {
	for i := range cp.Challenges {
		ch := &cp.Challenges[i]
		if !ch.Presented || ch.Cleaned {
			continue
		}
		if opts.DNS == nil || opts.SaveCheckpoint == nil {
			return errors.New("DNS cleanup and checkpoint callbacks are required")
		}
		if err := opts.DNS.Cleanup(ctx, *ch); err != nil {
			return err
		}
		ch.Cleaned = true
		if err := opts.SaveCheckpoint(ctx, *cp); err != nil {
			return err
		}
	}
	return nil
}
func chainIssuer(chain []byte, wanted string) bool {
	for {
		block, rest := pem.Decode(chain)
		if block == nil {
			return false
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil && (cert.Issuer.CommonName == wanted || cert.Subject.CommonName == wanted) {
			return true
		}
		chain = rest
	}
}
func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func generateKey(kind string, size int) (string, error) {
	var key crypto.PrivateKey
	var err error
	switch strings.ToUpper(kind) {
	case "ECC", "ECDSA", "EC":
		var curve elliptic.Curve
		switch size {
		case 0, 384:
			curve = elliptic.P384()
		case 256:
			curve = elliptic.P256()
		default:
			return "", errors.New("EC key size must be 256 or 384")
		}
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "", "RSA":
		if size == 0 {
			size = 2048
		}
		if size != 2048 && size != 3072 && size != 4096 {
			return "", errors.New("RSA key size must be 2048, 3072 or 4096")
		}
		key, err = rsa.GenerateKey(rand.Reader, size)
	default:
		return "", errors.New("key type must be RSA or ECC")
	}
	if err != nil {
		return "", err
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})), nil
}
func validateDomains(values []string, max int, wildcard bool) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		prefix := ""
		if strings.HasPrefix(value, "*.") {
			if !wildcard {
				return nil, errors.New("issuer does not support wildcard certificates")
			}
			prefix = "*."
			value = value[2:]
		}
		ascii, err := idna.Lookup.ToASCII(value)
		if err != nil || ascii == "" || !strings.Contains(ascii, ".") || len(ascii) > 253 {
			return nil, errors.New("invalid certificate domain")
		}
		if net.ParseIP(ascii) != nil {
			return nil, errors.New("IP addresses are not supported by DNS certificate issuers")
		}
		for _, label := range strings.Split(ascii, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, errors.New("invalid certificate domain label")
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
					return nil, errors.New("invalid certificate domain label")
				}
			}
		}
		ascii = prefix + ascii
		if !seen[ascii] {
			out = append(out, ascii)
			seen[ascii] = true
		}
	}
	if len(out) == 0 || len(out) > max {
		return nil, fmt.Errorf("issuer accepts 1–%d domains", max)
	}
	return out, nil
}
func ParseResult(chain, key string) (*Result, error) {
	pair, err := tls.X509KeyPair([]byte(chain), []byte(key))
	if err != nil {
		return nil, fmt.Errorf("certificate and private key do not match: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(leaf.Raw)
	return &Result{Fullchain: chain, PrivateKey: key, Issuer: leaf.Issuer.CommonName, Subject: leaf.Subject.CommonName, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Fingerprint: hex.EncodeToString(hash[:])}, nil
}
func checkpointRequest(cp *Checkpoint, request Request, domains []string) error {
	if cp.Metadata == nil {
		cp.Metadata = map[string]any{}
	}
	raw, _ := json.Marshal(struct {
		Domains []string
		KeyType string
		KeySize int
	}{domains, strings.ToUpper(request.KeyType), request.KeySize})
	current := string(raw)
	if previous, ok := cp.Metadata["request"].(string); ok && previous != current {
		return errors.New("certificate request differs from its persisted checkpoint; create a new order")
	}
	cp.Metadata["request"] = current
	return nil
}
func verifyResultDomains(result *Result, domains []string) error {
	block, _ := pem.Decode([]byte(result.Fullchain))
	if block == nil {
		return errors.New("certificate PEM missing")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			found := false
			for _, san := range leaf.DNSNames {
				if strings.EqualFold(san, domain) {
					found = true
					break
				}
			}
			if !found {
				return errors.New("issued certificate omits requested wildcard domain")
			}
		} else if err := leaf.VerifyHostname(domain); err != nil {
			return errors.New("issued certificate does not cover all requested domains")
		}
	}
	return nil
}
