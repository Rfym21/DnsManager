package automation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	certprovider "github.com/dns-manager/dnsmgr/server/internal/providers/cert"
	deployprovider "github.com/dns-manager/dnsmgr/server/internal/providers/deploy"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/redaction"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	mdns "github.com/miekg/dns"
)

type IssuerAccountData struct {
	Provider string                    `json:"provider"`
	Config   map[string]string         `json:"config"`
	State    certprovider.AccountState `json:"state"`
}
type DeployAccountData struct {
	Provider string            `json:"provider"`
	Config   map[string]string `json:"config"`
}
type CertificateData struct {
	AccountID       string                  `json:"account_id"`
	Domains         []string                `json:"domains"`
	KeyType         string                  `json:"key_type"`
	KeySize         int                     `json:"key_size"`
	AutoRenew       bool                    `json:"auto_renew"`
	RenewBeforeDays int                     `json:"renew_before_days"`
	PreferredChain  string                  `json:"preferred_chain,omitempty"`
	Staging         bool                    `json:"staging"`
	Checkpoint      certprovider.Checkpoint `json:"checkpoint"`
	Status          string                  `json:"status"`
	Fullchain       string                  `json:"fullchain,omitempty"`
	PrivateKey      string                  `json:"private_key,omitempty"`
	Issuer          string                  `json:"issuer,omitempty"`
	NotBefore       time.Time               `json:"not_before,omitempty"`
	NotAfter        time.Time               `json:"not_after,omitempty"`
	Fingerprint     string                  `json:"fingerprint,omitempty"`
}
type DeploymentData struct {
	AccountID           string                `json:"account_id"`
	CertificateID       string                `json:"certificate_id"`
	Target              map[string]string     `json:"target"`
	Info                deployprovider.Info   `json:"info"`
	AutoDeploy          bool                  `json:"auto_deploy"`
	DeployedFingerprint string                `json:"deployed_fingerprint,omitempty"`
	LastRun             time.Time             `json:"last_run,omitempty"`
	Window              DeploymentWindow      `json:"window"`
	RetryPolicy         DeploymentRetryPolicy `json:"retry_policy"`
}

func (r *Runner) CertificateHandlers() map[string]Handler {
	return map[string]Handler{"certificates": r.certificate, "deployments": r.deployment, "issuer_accounts": r.issuerAccount, "deploy_accounts": r.deployAccount}
}
func (r *Runner) logger(j store.Job) certprovider.Logger {
	return func(ctx context.Context, message string, data map[string]any) {
		r.Store.AddJobEvent(ctx, j, "info", message, safeLogData(data))
	}
}
func safeLogData(data map[string]any) map[string]any {
	if data == nil {
		return nil
	}
	raw, _ := json.Marshal(data)
	var normalized map[string]any
	json.Unmarshal(raw, &normalized)
	return redaction.Value(normalized).(map[string]any)
}
func (r *Runner) issuerAccount(ctx context.Context, j store.Job) (any, error) {
	o, err := r.Store.Object(ctx, j.ResourceID)
	if err != nil {
		return nil, err
	}
	var d IssuerAccountData
	if err = json.Unmarshal(o.Data, &d); err != nil {
		return nil, err
	}
	client, err := r.Store.HTTPClient(ctx, d.Config, 25*time.Second)
	if err != nil {
		return nil, err
	}
	provider, err := certprovider.New(d.Provider, d.Config, certprovider.Options{Logger: r.logger(j), HTTPClient: client})
	if err != nil {
		return nil, err
	}
	state, err := provider.Register(ctx, d.State)
	if err != nil {
		return nil, err
	}
	if _, err = r.Store.SaveObjectRuntime(ctx, o, j, map[string]any{"state": state}, "", nil); err != nil {
		return nil, err
	}
	return map[string]bool{"connected": true}, nil
}
func (r *Runner) deployOptions(ctx context.Context, j store.Job) deployprovider.Options {
	var settings struct {
		AllowedDirectories []string `json:"allowed_directories"`
		RemoteDirectories  []string `json:"remote_allowed_directories"`
		TrustedHooks       bool     `json:"allow_trusted_hooks"`
	}
	r.Store.Setting(ctx, "deployment_security", &settings)
	return deployprovider.Options{AllowedDirectories: settings.AllowedDirectories, RemoteAllowedDirectories: settings.RemoteDirectories, AllowTrustedHooks: settings.TrustedHooks, Logger: deployprovider.Logger(r.logger(j)), Checkpoint: func(ctx context.Context, info deployprovider.Info) error { return r.Store.CheckpointJob(ctx, j, info) }}
}
func (r *Runner) deployAccount(ctx context.Context, j store.Job) (any, error) {
	o, err := r.Store.Object(ctx, j.ResourceID)
	if err != nil {
		return nil, err
	}
	var d DeployAccountData
	if err = json.Unmarshal(o.Data, &d); err != nil {
		return nil, err
	}
	opts := r.deployOptions(ctx, j)
	opts.HTTPClient, err = r.Store.HTTPClient(ctx, d.Config, 25*time.Second)
	if err != nil {
		return nil, err
	}
	provider, err := deployprovider.New(d.Provider, d.Config, opts)
	if err != nil {
		return nil, err
	}
	if err = provider.Validate(ctx); err != nil {
		return nil, err
	}
	return map[string]bool{"connected": true}, nil
}
func (r *Runner) certificate(ctx context.Context, j store.Job) (any, error) {
	o, err := r.Store.Object(ctx, j.ResourceID)
	if err != nil {
		return nil, err
	}
	var d CertificateData
	if err = json.Unmarshal(o.Data, &d); err != nil {
		return nil, err
	}
	if d.AccountID == "" {
		return nil, errors.New("manually imported certificates have no issuer account")
	}
	issuerObject, err := r.Store.Object(ctx, d.AccountID)
	if err != nil {
		return nil, err
	}
	if issuerObject.Kind != "issuer_accounts" {
		return nil, errors.New("invalid issuer account")
	}
	var issuer IssuerAccountData
	if err = json.Unmarshal(issuerObject.Data, &issuer); err != nil {
		return nil, err
	}
	if issuer.Config == nil {
		issuer.Config = map[string]string{}
	}
	if d.Staging {
		if issuer.Provider != "letsencrypt" && issuer.Provider != "google" {
			return nil, errors.New("this issuer has no staging directory; select a separate test issuer")
		}
		if issuer.Config["mode"] != "staging" {
			return nil, errors.New("staging orders require a separate issuer account configured for staging")
		}
	}
	client, err := r.Store.HTTPClient(ctx, issuer.Config, 25*time.Second)
	if err != nil {
		return nil, err
	}
	provider, err := certprovider.New(issuer.Provider, issuer.Config, certprovider.Options{Logger: r.logger(j), HTTPClient: client})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Action string `json:"action"`
	}
	json.Unmarshal(j.Payload, &payload)
	cp := d.Checkpoint
	if len(j.Checkpoint) > 0 {
		if err = json.Unmarshal(j.Checkpoint, &cp); err != nil {
			return nil, err
		}
	}
	if cp.Account.KeyPEM == "" {
		cp.Account = issuer.State
	}
	save := func(ctx context.Context, next certprovider.Checkpoint) error {
		if err := r.check(ctx, j); err != nil {
			return err
		}
		if err := r.Store.CheckpointJob(ctx, j, next); err != nil {
			return err
		}
		if next.Account.KeyPEM != "" {
			if _, err := r.Store.SaveObjectRuntime(ctx, issuerObject, j, map[string]any{"state": next.Account}, "", nil); err != nil {
				return err
			}
		}
		_, err := r.Store.SaveObjectRuntime(ctx, o, j, map[string]any{"checkpoint": next, "status": next.Stage}, "", nil)
		return err
	}
	callback := &challengeDNS{runner: r, job: j}
	provider, err = certprovider.New(issuer.Provider, issuer.Config, certprovider.Options{Logger: r.logger(j), DNS: callback, SaveCheckpoint: save, HTTPClient: client})
	if err != nil {
		return nil, err
	}
	if payload.Action == "revoke" {
		if err = r.check(ctx, j); err != nil {
			return nil, err
		}
		if err = provider.Revoke(ctx, &cp, d.Fullchain); err != nil {
			return nil, err
		}
		d.Status = "revoked"
		d.AutoRenew = false
	} else if payload.Action == "cancel" {
		if err = r.check(ctx, j); err != nil {
			return nil, err
		}
		if err = callback.cleanupResourceIntents(ctx); err != nil {
			return nil, err
		}
		isACME := issuer.Provider != "tencent" && issuer.Provider != "aliyun" && issuer.Provider != "ucloud" && issuer.Provider != "huoshan"
		if isACME && cp.OrderURL == "" && cp.Stage == "creating_order" {
			return nil, &UnknownError{Message: "CA订单提交结果未确认，已清理DNS记录；请核对CA订单后取消"}
		}
		for marker, value := range cp.Metadata {
			if strings.HasPrefix(marker, "submitted:") && value == true {
				return nil, &UnknownError{Message: "证书订单提交结果未确认，已清理DNS记录；请核对平台订单后取消"}
			}
		}
		for index := range cp.Challenges {
			ch := &cp.Challenges[index]
			if ch.Presented && !ch.Cleaned {
				if err = callback.Cleanup(ctx, *ch); err != nil {
					return nil, err
				}
				ch.Cleaned = true
				if err = save(ctx, cp); err != nil {
					return nil, err
				}
			}
		}
		if certificateCheckpointHasOrder(issuer.Provider, cp) {
			if err = provider.Cancel(ctx, &cp); err != nil {
				return nil, err
			}
		}
		cp.Stage = "cancelled"
		if err = save(ctx, cp); err != nil {
			return nil, err
		}
		d.Status = "cancelled"
		d.AutoRenew = false
	} else {
		if payload.Action == "renew" && cp.Stage == "issued" {
			cp = certprovider.Checkpoint{Account: cp.Account}
		}
		result, e := provider.Issue(ctx, certprovider.Request{Domains: d.Domains, KeyType: d.KeyType, KeySize: d.KeySize, PreferredChain: d.PreferredChain}, &cp, callback, save)
		if e != nil {
			var uncertain interface{ UnknownResult() bool }
			if errors.As(e, &uncertain) && uncertain.UnknownResult() {
				return nil, &UnknownError{Message: e.Error()}
			}
			return nil, e
		}
		d.Fullchain = result.Fullchain
		d.PrivateKey = result.PrivateKey
		d.Issuer = result.Issuer
		d.NotBefore = result.NotBefore
		d.NotAfter = result.NotAfter
		d.Fingerprint = result.Fingerprint
		d.Status = "issued"
		d.Checkpoint = cp
	}
	d.Checkpoint = cp
	if _, err = r.Store.SaveObjectRuntime(ctx, o, j, map[string]any{"fullchain": d.Fullchain, "private_key": d.PrivateKey, "issuer": d.Issuer, "not_before": d.NotBefore, "not_after": d.NotAfter, "fingerprint": d.Fingerprint, "status": d.Status, "checkpoint": d.Checkpoint, "auto_renew": d.AutoRenew}, "", nil); err != nil {
		return nil, err
	}
	r.Store.Audit(ctx, j.OwnerID, "certificate."+payload.Action, "certificate", o.ID, "", "", map[string]string{"job_id": j.ID, "status": d.Status})
	return map[string]any{"status": d.Status, "fingerprint": d.Fingerprint, "not_after": d.NotAfter}, nil
}
func (r *Runner) deployment(ctx context.Context, j store.Job) (any, error) {
	o, err := r.Store.Object(ctx, j.ResourceID)
	if err != nil {
		return nil, err
	}
	var d DeploymentData
	if err = json.Unmarshal(o.Data, &d); err != nil {
		return nil, err
	}
	policy, err := NormalizeDeploymentRetryPolicy(d.RetryPolicy)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Action string `json:"action"`
	}
	json.Unmarshal(j.Payload, &payload)
	if payload.Action != "test" {
		next, err := deploymentWindowNext(d.Window, time.Now())
		if err != nil {
			return nil, err
		}
		if next.After(time.Now()) {
			return nil, &DeferredError{Err: errors.New("等待配置的部署窗口"), Until: next}
		}
	}
	account, err := r.Store.Object(ctx, d.AccountID)
	if err != nil {
		return nil, err
	}
	if account.Kind != "deploy_accounts" {
		return nil, errors.New("invalid deployment account")
	}
	var config DeployAccountData
	if err = json.Unmarshal(account.Data, &config); err != nil {
		return nil, err
	}
	certificate, err := r.Store.Object(ctx, d.CertificateID)
	if err != nil {
		return nil, err
	}
	var cert CertificateData
	if err = json.Unmarshal(certificate.Data, &cert); err != nil {
		return nil, err
	}
	if cert.Status != "issued" {
		return nil, errors.New("only issued certificates can be deployed")
	}
	if _, err = certprovider.ParseResult(cert.Fullchain, cert.PrivateKey); err != nil {
		return nil, err
	}
	opts := r.deployOptions(ctx, j)
	opts.HTTPClient, err = r.Store.HTTPClient(ctx, config.Config, 25*time.Second)
	if err != nil {
		return nil, err
	}
	observedClient, acceptedRequests := observeDeploymentClient(opts.HTTPClient)
	opts.HTTPClient = observedClient
	opts.Checkpoint = func(ctx context.Context, info deployprovider.Info) error {
		info = deploymentPendingInfo(info, j.ID, cert.Fingerprint)
		if err := r.Store.CheckpointJob(ctx, j, info); err != nil {
			return err
		}
		_, err := r.Store.SaveObjectRuntime(ctx, o, j, map[string]any{"info": info}, "", nil)
		return err
	}
	provider, err := deployprovider.New(config.Provider, config.Config, opts)
	if err != nil {
		return nil, err
	}
	if payload.Action == "test" {
		if err = provider.Validate(ctx); err != nil {
			return nil, err
		}
		return map[string]bool{"connected": true}, nil
	}
	if err = r.check(ctx, j); err != nil {
		return nil, err
	}
	if deploymentSubmissionPending(d.Info) {
		return nil, &UnknownError{Message: "上次部署已提交但结果未确认，请核对外部平台后处理"}
	}
	if len(j.Checkpoint) > 0 {
		if err = json.Unmarshal(j.Checkpoint, &d.Info); err != nil {
			return nil, errors.New("invalid deployment checkpoint")
		}
	}
	if complete := deploymentCompletedResult(d.Info, j.ID, cert.Fingerprint); complete != nil {
		return complete, nil
	}
	if deploymentSubmissionPending(d.Info) {
		return nil, &UnknownError{Message: "上次部署已提交但结果未确认，请核对外部平台后处理"}
	}
	d.Info = deploymentPendingInfo(d.Info, j.ID, cert.Fingerprint)
	if err = opts.Checkpoint(ctx, d.Info); err != nil {
		return nil, err
	}
	info, err := provider.Deploy(ctx, cert.Fullchain, cert.PrivateKey, deployprovider.Target{Config: d.Target, Domains: cert.Domains}, d.Info)
	if err != nil {
		// Provider errors can echo submitted material in an ordinary message
		// field. Remove it before persisting item results or job errors.
		info = redactDeploymentInfo(info, config.Config, d.Target, cert.Fullchain, cert.PrivateKey)
		message := redactDeploymentText(err.Error(), config.Config, d.Target, cert.Fullchain, cert.PrivateKey)
		var partial *deployprovider.PartialError
		if errors.As(err, &partial) {
			if partial.UnknownResult() {
				return map[string]any{"info": safeLogData(info)}, &UnknownError{Message: "部分部署请求结果未确认，请核对各目标外部状态"}
			}
			return map[string]any{"info": safeLogData(info)}, &PartialError{Message: partial.Error()}
		}
		var safeRetry interface{ SafeToRetry() bool }
		var rejected interface{ ConfirmedRejection() bool }
		var uncertain interface{ UnknownResult() bool }
		confirmed := errors.As(err, &rejected) && rejected.ConfirmedRejection()
		if errors.As(err, &uncertain) && uncertain.UnknownResult() {
			confirmed = false
		}
		if acceptedRequests.accepted.Load() > 0 {
			confirmed = false
		}
		if confirmed && errors.As(err, &safeRetry) {
			if clearErr := r.clearDeploymentSubmission(ctx, o, j, info); clearErr != nil {
				return nil, clearErr
			}
			if safeRetry.SafeToRetry() {
				return nil, &RetryError{Err: errors.New(message), After: time.Duration(policy.DelaySeconds) * time.Second}
			}
			return nil, errors.New(message)
		}
		if errors.Is(err, store.ErrLeaseLost) || errors.Is(err, store.ErrCancelled) || errors.Is(err, context.Canceled) {
			return nil, err
		}
		return nil, &UnknownError{Message: "部署请求结果尚未确认，请核对外部平台后处理"}
	}
	info = deploymentClearMarkers(info)
	d.Info = info
	d.DeployedFingerprint = cert.Fingerprint
	d.LastRun = time.Now().UTC()
	if _, err = r.Store.SaveObjectRuntime(ctx, o, j, map[string]any{"info": info, "deployed_fingerprint": d.DeployedFingerprint, "last_run": d.LastRun}, "", nil); err != nil {
		if errors.Is(err, store.ErrLeaseLost) || errors.Is(err, store.ErrCancelled) {
			return nil, err
		}
		return nil, &UnknownError{Message: "远端部署已完成，但本地完成状态未保存，请核对部署结果"}
	}
	if err = r.Store.CheckpointJob(ctx, j, deploymentCompleteInfo(info, j.ID, cert.Fingerprint)); err != nil {
		return nil, err
	}
	return map[string]any{"fingerprint": cert.Fingerprint, "info": safeLogData(info)}, nil
}

type dnsReceipt struct {
	DomainID string `json:"domain_id"`
	RecordID string `json:"record_id"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Created  bool   `json:"created"`
}
type challengeDNS struct {
	runner *Runner
	job    store.Job
}

func (c *challengeDNS) Present(ctx context.Context, ch certprovider.Challenge) (json.RawMessage, error) {
	p, err := c.runner.principal(ctx, c.job)
	if err != nil {
		return nil, err
	}
	zones, err := c.runner.Store.Domains(ctx, p)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSuffix(ch.Name, ".")
	// Resolve explicit application delegation first, then actual CNAME.
	delegations, err := c.runner.Store.Objects(ctx, "delegations")
	if err != nil {
		return nil, err
	}
	for _, o := range delegations {
		var d struct {
			Domain string `json:"domain"`
			Target string `json:"target"`
		}
		if o.Active && json.Unmarshal(o.Data, &d) == nil && (d.Domain == ch.Domain || name == "_acme-challenge."+strings.TrimPrefix(d.Domain, "*.")) {
			name = strings.TrimSuffix(d.Target, ".")
			break
		}
	}
	lookup := c.runner.LookupCNAME
	if lookup == nil {
		lookup = net.DefaultResolver.LookupCNAME
	}
	resolved, e := lookup(ctx, name)
	if e == nil && resolved != "" {
		name = strings.TrimSuffix(resolved, ".")
	} else if e != nil {
		var dnsError *net.DNSError
		if !errors.As(e, &dnsError) || !dnsError.IsNotFound {
			return nil, errors.New("DNS CNAME委托查询暂时失败")
		}
	}
	var zone *store.Domain
	for i := range zones {
		d := &zones[i]
		if name == d.ASCIIName || strings.HasSuffix(name, "."+d.ASCIIName) {
			if zone == nil || len(d.ASCIIName) > len(zone.ASCIIName) {
				zone = d
			}
		}
	}
	if zone == nil {
		return nil, fmt.Errorf("DNS challenge zone not managed for %s", name)
	}
	_, provider, err := c.runner.provider(ctx, p, zone.ID, "dns:write")
	if err != nil {
		return nil, err
	}
	relative := strings.TrimSuffix(name, "."+zone.ASCIIName)
	if relative == zone.ASCIIName {
		relative = "@"
	}
	keyHash := sha256.Sum256([]byte(name + "\x00" + ch.Type + "\x00" + ch.Value))
	intentKey := hex.EncodeToString(keyHash[:])
	var state, recordID string
	intentErr := c.runner.Store.DB.QueryRowContext(ctx, "SELECT state,record_id FROM dns_challenge_intents WHERE job_id=? AND challenge_key=?", c.job.ID, intentKey).Scan(&state, &recordID)
	if intentErr != nil && !errors.Is(intentErr, sql.ErrNoRows) {
		return nil, intentErr
	}
	hadIntent := intentErr == nil
	for pageNumber := 1; pageNumber <= 100; pageNumber++ {
		page, e := provider.ListRecords(ctx, dns.ListOptions{Name: relative, Type: ch.Type, Page: pageNumber, PageSize: 100})
		if e != nil {
			return nil, e
		}
		for _, record := range page.Rows {
			matches := record.Value == ch.Value
			for _, value := range record.Values {
				matches = matches || value == ch.Value
			}
			if record.Name == relative && record.Type == ch.Type && matches {
				if hadIntent {
					if _, e = c.runner.Store.DB.ExecContext(ctx, "UPDATE dns_challenge_intents SET state='confirmed',record_id=?,updated_at=UTC_TIMESTAMP(6) WHERE job_id=? AND challenge_key=?", record.ID, c.job.ID, intentKey); e != nil {
						return nil, e
					}
				}
				b, _ := json.Marshal(dnsReceipt{DomainID: zone.ID, RecordID: record.ID, Name: relative, Value: ch.Value, Created: hadIntent})
				return b, nil
			}
		}
		if len(page.Rows) < 100 || pageNumber*100 >= page.Total {
			break
		}
		if pageNumber == 100 {
			return nil, errors.New("DNS challenge record scan exceeded page limit")
		}
	}
	if hadIntent {
		return nil, &UnknownError{Message: "DNS验证记录先前提交过，但尚未确认；请核对平台记录后重试"}
	}
	if err = c.runner.check(ctx, c.job); err != nil {
		return nil, err
	}
	ttl, e := provider.MinTTL(ctx)
	if e != nil {
		return nil, e
	}
	lines, e := provider.Lines(ctx)
	if e != nil {
		return nil, e
	}
	line := "default"
	if len(lines) > 0 {
		line = lines[0].ID
	}
	intent, err := c.runner.Store.Encrypt("dns-intent:"+c.job.ID+":"+intentKey, map[string]any{"name": relative, "type": ch.Type, "value": ch.Value, "domain_id": zone.ID})
	if err != nil {
		return nil, err
	}
	mutationResult, err := c.runner.Store.DB.ExecContext(ctx, "INSERT INTO dns_challenge_intents(job_id,challenge_key,domain_id,intent_ciphertext,state,created_at,updated_at) SELECT ?,?,?,?,'submitted',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6) FROM jobs WHERE id=? AND state='running' AND lease_owner=? AND fencing_token=? AND lease_until>UTC_TIMESTAMP(6)", c.job.ID, intentKey, zone.ID, intent, c.job.ID, c.job.LeaseOwner, c.job.FencingToken)
	if err != nil {
		return nil, err
	}
	count, err := mutationResult.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, store.ErrLeaseLost
	}
	record, err := provider.CreateRecord(ctx, dns.Record{Name: relative, Type: ch.Type, Value: ch.Value, TTL: max(ttl, 60), Line: line, Enabled: true})
	if err != nil {
		return nil, err
	}
	if _, err = c.runner.Store.DB.ExecContext(ctx, "UPDATE dns_challenge_intents SET state='confirmed',record_id=?,updated_at=UTC_TIMESTAMP(6) WHERE job_id=? AND challenge_key=?", record.ID, c.job.ID, intentKey); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(dnsReceipt{DomainID: zone.ID, RecordID: record.ID, Name: relative, Value: ch.Value, Created: true})
	return b, nil
}
func (c *challengeDNS) Wait(ctx context.Context, ch certprovider.Challenge) error {
	if ch.Type != "TXT" {
		return nil
	}
	name := mdns.Fqdn(ch.Name)
	var receipt dnsReceipt
	if len(ch.Receipt) > 0 && json.Unmarshal(ch.Receipt, &receipt) == nil && receipt.DomainID != "" {
		domain, err := c.runner.Store.Domain(ctx, receipt.DomainID)
		if err != nil {
			return err
		}
		zone := domain.ASCIIName
		if zone == "" {
			zone = domain.Name
		}
		if receipt.Name == "@" {
			name = mdns.Fqdn(zone)
		} else {
			name = mdns.Fqdn(receipt.Name + "." + zone)
		}
	}
	var servers []string
	cfg, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil {
		servers = cfg.Servers
	}
	if len(servers) == 0 {
		servers = []string{"1.1.1.1"}
	}
	deadline := time.NewTimer(5 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	client := &mdns.Client{Timeout: 3 * time.Second}
	for {
		for _, server := range servers {
			msg := new(mdns.Msg)
			msg.SetQuestion(name, mdns.TypeTXT)
			res, _, err := client.ExchangeContext(ctx, msg, netAddress(server))
			if err != nil {
				continue
			}
			for _, rr := range res.Answer {
				if txt, ok := rr.(*mdns.TXT); ok && strings.Join(txt.Txt, "") == ch.Value {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return &RetryError{Err: errors.New("waiting for DNS challenge propagation"), After: 30 * time.Second}
		case <-ticker.C:
		}
	}
}
func netAddress(server string) string {
	if strings.Contains(server, ":") {
		return "[" + server + "]:53"
	}
	return server + ":53"
}
func (c *challengeDNS) Cleanup(ctx context.Context, ch certprovider.Challenge) error {
	var receipt dnsReceipt
	if json.Unmarshal(ch.Receipt, &receipt) != nil {
		return errors.New("invalid DNS challenge receipt")
	}
	if !receipt.Created {
		return nil
	}
	p, err := c.runner.principal(ctx, c.job)
	if err != nil {
		return err
	}
	_, provider, err := c.runner.provider(ctx, p, receipt.DomainID, "dns:write")
	if err != nil {
		return err
	}
	current, err := provider.GetRecord(ctx, receipt.RecordID)
	if errors.Is(err, dns.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Name != receipt.Name || current.Value != receipt.Value || !strings.EqualFold(current.Type, ch.Type) || len(current.Values) > 1 {
		return errors.New("DNS challenge changed; refusing to delete another value")
	}
	return provider.DeleteRecord(ctx, receipt.RecordID)
}
