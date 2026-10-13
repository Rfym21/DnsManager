package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/dns-manager/dnsmgr/server/internal/automation"
	certprovider "github.com/dns-manager/dnsmgr/server/internal/providers/cert"
	deployprovider "github.com/dns-manager/dnsmgr/server/internal/providers/deploy"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/dns-manager/dnsmgr/server/internal/transport"
	"strings"
	"time"
)

// Configuration edits cannot replace issuer state, DNS receipts, fingerprints,
// or checkpoints. Preserve runtime fields and existing metadata.
func configurationData(kind string, before, incoming json.RawMessage) (json.RawMessage, error) {
	old, next := map[string]json.RawMessage{}, map[string]json.RawMessage{}
	if len(before) > 0 && json.Unmarshal(before, &old) != nil {
		return nil, errors.New("existing object is invalid")
	}
	if json.Unmarshal(incoming, &next) != nil || next == nil {
		return nil, errors.New("配置必须是 JSON 对象")
	}
	if len(before) > 0 && (kind == "issuer_accounts" || kind == "deploy_accounts" || kind == "notification_channels") {
		if value, ok := next["provider"]; ok && string(value) != string(old["provider"]) {
			return nil, errors.New("请新建账户或渠道来更换平台，已有密钥不能跨平台复用")
		}
	}
	if kind == "certificates" && len(before) > 0 {
		for _, key := range []string{"account_id", "domains", "key_type", "key_size", "staging", "preferred_chain"} {
			if value, ok := next[key]; ok && string(value) != string(old[key]) && !(len(old[key]) == 0 && (string(value) == `""` || string(value) == "false" || string(value) == "0")) {
				return nil, errors.New("请新建证书配置来更换签发账户、域名或密钥参数，已有签发结果需保持一致")
			}
		}
	}
	allowed := map[string][]string{
		"issuer_accounts": {"provider", "config"}, "deploy_accounts": {"provider", "config"},
		"certificates":  {"account_id", "domains", "key_type", "key_size", "auto_renew", "renew_before_days", "staging", "preferred_chain"},
		"deployments":   {"account_id", "certificate_id", "target", "auto_deploy", "window", "retry_policy"},
		"monitors":      {"record_id", "name", "probe", "target", "port", "timeout_seconds", "tls_verify", "host", "expected_status", "expected_body", "connect_ip", "proxy_url", "proxy", "frequency_seconds", "failures", "recoveries", "mode", "main_value", "backup_value", "proxied", "condition_ids", "condition_threshold"},
		"schedules":     {"record_id", "operation", "record", "schedule"},
		"optimizations": {"source_url", "source_provider", "source_config", "ip_types", "line_mode", "ip_type", "record_names", "line", "ttl", "record_count", "interval_seconds"},
		"delegations":   {"domain", "target", "account_domain_id"}, "aliases": {"alias", "domain_id"}, "categories": {"name", "remark"},
		"notification_channels": {"provider", "config", "events"}, "proxy_profiles": {"url", "test_url"},
	}[kind]
	for _, key := range allowed {
		if value, ok := next[key]; ok {
			old[key] = value
		}
	}
	if kind == "certificates" {
		// Manual PEM is accepted only at creation and parsed on the server.
		var id string
		json.Unmarshal(old["account_id"], &id)
		if len(before) == 0 && id == "" {
			old["fullchain"] = next["fullchain"]
			old["private_key"] = next["private_key"]
		}
	}
	return json.Marshal(old)
}
func (a *API) validateReferences(ctx context.Context, o store.Object) error {
	var data map[string]json.RawMessage
	if json.Unmarshal(o.Data, &data) != nil {
		return errors.New("invalid object data")
	}
	ref := func(key, kind string, optional bool) error {
		var id string
		json.Unmarshal(data[key], &id)
		if id == "" && optional {
			return nil
		}
		if id == "" {
			return errors.New("需要选择关联账户或资源")
		}
		target, err := a.Store.Object(ctx, id)
		if err != nil || target.Kind != kind {
			return errors.New("关联资源不存在或类型不正确")
		}
		return nil
	}
	switch o.Kind {
	case "certificates":
		if err := ref("account_id", "issuer_accounts", true); err != nil {
			return err
		}
		var d automation.CertificateData
		json.Unmarshal(o.Data, &d)
		for _, name := range d.Domains {
			if _, err := dns.CanonicalName(strings.TrimPrefix(name, "*.")); err != nil {
				return errors.New("证书域名格式不正确")
			}
		}
	case "deployments":
		if err := ref("account_id", "deploy_accounts", false); err != nil {
			return err
		}
		if err := ref("certificate_id", "certificates", false); err != nil {
			return err
		}
	case "issuer_accounts", "deploy_accounts":
		var d automation.DeployAccountData
		json.Unmarshal(o.Data, &d)
		if o.Kind == "issuer_accounts" {
			if _, err := certprovider.New(d.Provider, d.Config, certprovider.Options{}); err != nil {
				return errors.New("签发平台或配置不正确")
			}
		} else if !deployprovider.Implemented(d.Provider) {
			return errors.New("部署平台不正确")
		}
	case "delegations", "aliases":
		key := "account_domain_id"
		if o.Kind == "aliases" {
			key = "domain_id"
		}
		var id string
		json.Unmarshal(data[key], &id)
		if id != "" {
			if _, err := a.Store.Domain(ctx, id); err != nil {
				return errors.New("关联管理域名不存在")
			}
		}
	case "proxy_profiles":
		var d struct {
			URL string `json:"url"`
		}
		json.Unmarshal(o.Data, &d)
		if d.URL == "" {
			return errors.New("需要填写代理 URL")
		}
		if _, err := transport.Client(d.URL, time.Second); err != nil {
			return err
		}
	}
	return nil
}

func (a *API) objectInUse(ctx context.Context, id string) (bool, error) {
	var count int
	if err := a.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM jobs WHERE resource_id=? AND state IN ('queued','running','retry','unknown')", id).Scan(&count); err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}
	rows, err := a.Store.DB.QueryContext(ctx, "SELECT id,data_ciphertext FROM objects WHERE id<>?", id)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var other, enc string
		if err = rows.Scan(&other, &enc); err != nil {
			return false, err
		}
		var data map[string]any
		if err = a.Store.Decrypt("object:"+other, enc, &data); err != nil {
			return false, err
		}
		for _, key := range []string{"account_id", "certificate_id", "condition_ids"} {
			switch value := data[key].(type) {
			case string:
				if value == id {
					return true, nil
				}
			case []any:
				for _, v := range value {
					if v == id {
						return true, nil
					}
				}
			}
		}
	}
	return false, rows.Err()
}
