package contracts

import (
	"github.com/dns-manager/dnsmgr/server/internal/automation"
	"github.com/dns-manager/dnsmgr/server/internal/domaininfo"
	"github.com/dns-manager/dnsmgr/server/internal/httpapi"
	"github.com/dns-manager/dnsmgr/server/internal/notifications"
	certprovider "github.com/dns-manager/dnsmgr/server/internal/providers/cert"
	deployprovider "github.com/dns-manager/dnsmgr/server/internal/providers/deploy"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/redaction"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"reflect"
)

var objectKinds = []string{"certificates", "issuer_accounts", "deploy_accounts", "deployments", "monitors", "schedules", "optimizations", "notification_channels", "delegations", "aliases", "categories", "proxy_profiles"}

func catalog(r *registry) {
	r.Schemas["DateTime"] = Schema{"type": "string", "format": "date-time"}
	r.register("DNSRecord", dns.Record{})
	r.Schemas["DNSAnswer"] = object(map[string]Schema{"name": scalar("string"), "type": scalar("string"), "ttl": Schema{"type": "integer", "minimum": 0, "maximum": 4294967295}, "value": scalar("string")}, "name", "type", "ttl", "value")
	r.Schemas["RecordCheckResult"] = object(map[string]Schema{"record": ref("DNSRecord"), "queryName": scalar("string"), "answers": array(ref("DNSAnswer")), "matched": scalar("boolean"), "status": enumeration("active", "mismatch", "not_found", "resolver_error"), "rcode": scalar("integer")}, "record", "queryName", "answers", "matched", "status", "rcode")
	r.Schemas["DNSRecordWrite"] = r.structSchema(reflect.TypeOf(dns.Record{}))
	writeProperties := r.Schemas["DNSRecordWrite"]["properties"].(map[string]Schema)
	r.Schemas["DNSRecordWrite"] = Schema{"anyOf": []Schema{object(writeProperties, "name", "type", "value"), object(writeProperties, "name", "type", "values")}}
	r.register("DNSCapabilities", dns.Capabilities{})
	r.register("DNSLine", dns.Line{})
	r.register("DNSGroup", dns.Group{})
	r.register("DNSAlias", dns.Alias{})
	r.register("DNSLog", dns.Log{})
	r.register("DNSWeightGroup", dns.WeightGroup{})
	r.register("ProviderDomain", dns.Domain{})
	r.register("DNSProvider", dns.Descriptor{})
	r.register("CertificateProvider", certprovider.Descriptor{})
	r.register("DeployProvider", deployprovider.Descriptor{})
	for name, category := range map[string]string{"CertificateProvider": "cert", "DeployProvider": "deploy"} {
		r.Schemas[name]["properties"].(map[string]Schema)["category"] = Schema{"const": category, "type": "string"}
		r.Schemas[name]["required"] = append(r.Schemas[name]["required"].([]string), "category")
	}
	r.Schemas["Provider"] = Schema{"oneOf": []Schema{ref("DNSProvider"), ref("CertificateProvider"), ref("DeployProvider")}}
	r.register("User", store.User{})
	r.register("Account", store.Account{})
	r.register("Domain", store.Domain{})
	r.register("ResourceObject", store.Object{})
	r.register("Job", store.Job{})
	r.Schemas["OptimizationQuota"] = object(map[string]Schema{"source_provider": enumeration("wetest", "hostmonit", "xingpingcn"), "unlimited": scalar("boolean"), "remaining": Schema{"type": "integer", "minimum": 0}}, "source_provider", "unlimited")
	r.Schemas["Job"]["properties"].(map[string]Schema)["result"] = described(ref("JSONValue"), "Redacted result varies by job.kind and action; optimization quota uses OptimizationQuota, batch results are represented by durable JobItems.")
	r.register("JobItem", store.JobItem{})
	r.register("JobEvent", store.JobEvent{})
	r.register("Grant", httpapi.Grant{})
	r.register("RegistryDates", domaininfo.Dates{})
	r.register("Schedule", automation.Schedule{})
	r.register("DeploymentWindow", automation.DeploymentWindow{})
	r.register("DeploymentRetryPolicy", automation.DeploymentRetryPolicy{})
	r.register("Probe", automation.ProbeSpec{})
	r.register("ProbeResult", automation.ProbeResult{})
	r.register("MonitorState", automation.MonitorState{})
	r.Schemas["User"]["properties"].(map[string]Schema)["role"] = enumeration("admin", "restricted")
	r.Schemas["Preferences"] = object(map[string]Schema{"theme": enumeration("light", "dark", "system"), "density": scalar("string"), "reduce_motion": scalar("boolean")})
	r.Schemas["User"]["properties"].(map[string]Schema)["preferences"] = nullable(ref("Preferences"))
	r.Schemas["DomainUser"] = object(map[string]Schema{"id": scalar("string"), "username": scalar("string"), "role": Schema{"type": "string", "const": "domain"}, "enabled": scalar("boolean")}, "id", "username", "role", "enabled")
	r.Schemas["Session"] = object(map[string]Schema{"user": Schema{"oneOf": []Schema{ref("User"), ref("DomainUser")}}, "csrf_token": scalar("string"), "domain_id": scalar("string"), "permissions": array(scalar("string"))}, "user", "csrf_token")
	r.Schemas["Error"] = object(map[string]Schema{"code": scalar("string"), "message": scalar("string"), "request_id": scalar("string")}, "code", "message", "request_id")
	r.Schemas["OK"] = object(map[string]Schema{"ok": Schema{"type": "boolean", "const": true}}, "ok")
	r.Schemas["Pagination"] = object(map[string]Schema{"total": scalar("integer")}, "total")
	r.Schemas["AccountDetail"] = r.structSchema(reflect.TypeOf(store.Account{}))
	r.Schemas["AccountDetail"]["properties"].(map[string]Schema)["config"] = described(nullable(dict(scalar("string"))), "Credentials and credential-bearing URL fields return an empty string; blank updates preserve existing secrets.")
	r.Schemas["AccountDetail"]["required"] = append(r.Schemas["AccountDetail"]["required"].([]string), "config")
	r.Schemas["JobDetail"] = object(map[string]Schema{"job": ref("Job"), "items": array(ref("JobItem"))}, "job", "items")
	r.Schemas["QueuedJob"] = object(map[string]Schema{"job": ref("Job")}, "job")
	r.Schemas["Token"] = object(map[string]Schema{"id": scalar("string"), "name": scalar("string"), "scopes": array(enumeration("dns:read", "dns:write", "admin")), "created_at": ref("DateTime"), "expires_at": ref("DateTime")}, "id", "name", "scopes", "created_at", "expires_at")
	r.Schemas["AuditEvent"] = object(map[string]Schema{"id": scalar("integer"), "actor_id": scalar("string"), "action": scalar("string"), "resource_type": scalar("string"), "resource_id": scalar("string"), "domain_id": nullable(scalar("string")), "request_id": scalar("string"), "detail": ref("JSONValue"), "created_at": ref("DateTime")}, "id", "actor_id", "action", "resource_type", "resource_id", "domain_id", "request_id", "detail", "created_at")
	r.Schemas["DomainDates"] = object(map[string]Schema{"registered_at": nullable(ref("DateTime")), "expires_at": nullable(ref("DateTime")), "checked_at": nullable(ref("DateTime")), "notice_at": nullable(ref("DateTime")), "expiry_notice_enabled": scalar("boolean")}, "registered_at", "expires_at", "checked_at", "notice_at", "expiry_notice_enabled")
	r.Schemas["ImportNotice"] = object(map[string]Schema{"row": scalar("integer"), "code": scalar("string"), "message": scalar("string")}, "row", "code", "message")
	importItem := r.structSchema(reflect.TypeOf(dns.Record{}))
	props := importItem["properties"].(map[string]Schema)
	for key, value := range map[string]Schema{"source_row": scalar("integer"), "line_name": scalar("string"), "line_fallback": scalar("boolean"), "valid": scalar("boolean")} {
		props[key] = value
	}
	importItem["required"] = append(importItem["required"].([]string), "source_row", "line_name", "line_fallback", "valid")
	r.Schemas["ImportItem"] = importItem
	r.Schemas["ImportSource"] = object(map[string]Schema{"filename": scalar("string"), "sheet": scalar("string"), "domain_id": scalar("string"), "domain_name": scalar("string"), "rows": scalar("integer"), "max_rows": scalar("integer")}, "filename", "sheet", "domain_id", "domain_name", "rows", "max_rows")
	r.Schemas["ImportPreview"] = object(map[string]Schema{"items": array(ref("ImportItem")), "issues": array(ref("ImportNotice")), "warnings": array(ref("ImportNotice")), "source": ref("ImportSource")}, "items", "issues", "warnings", "source")
	objectSchemas(r)
	cloudflareSchemas(r)
	settingsSchemas(r)
}

func objectSchemas(r *registry) {
	types := map[string]any{"CertificateData": automation.CertificateData{}, "IssuerAccountData": automation.IssuerAccountData{}, "DeployAccountData": automation.DeployAccountData{}, "DeploymentData": automation.DeploymentData{}, "MonitorData": automation.MonitorData{}, "ScheduleData": automation.ScheduleData{}, "OptimizationData": automation.OptimizationData{}, "NotificationData": notifications.Channel{}}
	kindNames := map[string]string{"certificates": "CertificateData", "issuer_accounts": "IssuerAccountData", "deploy_accounts": "DeployAccountData", "deployments": "DeploymentData", "monitors": "MonitorData", "schedules": "ScheduleData", "optimizations": "OptimizationData", "notification_channels": "NotificationData", "delegations": "DelegationData", "aliases": "AliasData", "categories": "CategoryData", "proxy_profiles": "ProxyProfileData"}
	for name, value := range types {
		r.register(name, value)
	}
	r.Schemas["DelegationData"] = object(map[string]Schema{"domain": scalar("string"), "target": scalar("string"), "account_domain_id": scalar("string")})
	r.Schemas["AliasData"] = object(map[string]Schema{"alias": scalar("string"), "domain_id": scalar("string")})
	r.Schemas["CategoryData"] = object(map[string]Schema{"name": scalar("string"), "remark": scalar("string")})
	r.Schemas["ProxyProfileData"] = object(map[string]Schema{"url": scalar("string"), "test_url": scalar("string")})
	allowed := map[string][]string{
		"certificates":    {"account_id", "domains", "key_type", "key_size", "auto_renew", "renew_before_days", "staging", "preferred_chain", "fullchain", "private_key"},
		"issuer_accounts": {"provider", "config"}, "deploy_accounts": {"provider", "config"},
		"deployments":           {"account_id", "certificate_id", "target", "auto_deploy", "window", "retry_policy"},
		"monitors":              {"record_id", "name", "probe", "target", "port", "timeout_seconds", "tls_verify", "host", "expected_status", "expected_body", "connect_ip", "proxy_url", "proxy", "frequency_seconds", "failures", "recoveries", "mode", "main_value", "backup_value", "proxied", "condition_ids", "condition_threshold"},
		"schedules":             {"record_id", "operation", "record", "schedule"},
		"optimizations":         {"source_url", "source_provider", "source_config", "ip_types", "line_mode", "ip_type", "record_names", "line", "ttl", "record_count", "interval_seconds"},
		"notification_channels": {"provider", "config", "events"}, "delegations": {"domain", "target", "account_domain_id"}, "aliases": {"alias", "domain_id"}, "categories": {"name", "remark"}, "proxy_profiles": {"url", "test_url"},
	}
	variants := []Schema{}
	configVariants := []Schema{}
	for _, kind := range objectKinds {
		name := kindNames[kind]
		data := r.Schemas[name]
		// Runtime aggregate shapes are redacted recursively. A secret aggregate
		// (e.g. private key/account key) may become "" instead of an object.
		data = redactSchema(data)
		data["additionalProperties"] = ref("JSONValue")
		delete(data, "required") // Older imported objects preserve sparse legacy data.
		r.Schemas[name] = data
		config := map[string]Schema{}
		for _, key := range allowed[kind] {
			if value, ok := data["properties"].(map[string]Schema)[key]; ok {
				config[key] = value
			}
		}
		for key, value := range config {
			if redaction.Key(key) {
				value = scalar("string")
				value["writeOnly"] = true
				config[key] = value
			}
		}
		configName := name + "Configuration"
		r.Schemas[configName] = object(config)
		configVariants = append(configVariants, ref(configName))
		variant := r.structSchema(reflect.TypeOf(store.Object{}))
		variant["properties"].(map[string]Schema)["kind"] = Schema{"type": "string", "const": kind}
		variant["properties"].(map[string]Schema)["data"] = ref(name)
		variantName := name + "Object"
		r.Schemas[variantName] = variant
		variants = append(variants, ref(variantName))
	}
	r.Schemas["ResourceObject"] = Schema{"oneOf": variants, "discriminator": map[string]any{"propertyName": "kind"}}
	// Kind is a path parameter, so configurations overlap. anyOf is correct;
	// oneOf would reject an otherwise valid partial update matching two variants.
	r.Schemas["ObjectConfiguration"] = Schema{"anyOf": configVariants, "description": "Use the configuration named for the kind path parameter. Only permitted fields are applied; execution state is server-owned. Certificate identity fields are immutable once created. Blank secret fields preserve their existing value."}
}

func redactSchema(s Schema) Schema {
	copy := Schema{}
	for key, value := range s {
		copy[key] = value
	}
	if properties, ok := s["properties"].(map[string]Schema); ok {
		out := map[string]Schema{}
		for key, value := range properties {
			if redaction.Key(key) {
				out[key] = Schema{"type": "string", "const": "", "description": "Redacted credential; never returned by ordinary resource endpoints."}
			} else {
				out[key] = redactSchema(value)
			}
		}
		copy["properties"] = out
	}
	if item, ok := s["items"].(Schema); ok {
		copy["items"] = redactSchema(item)
	}
	for _, union := range []string{"anyOf", "oneOf"} {
		if variants, ok := s[union].([]Schema); ok {
			items := make([]Schema, 0, len(variants))
			for _, item := range variants {
				items = append(items, redactSchema(item))
			}
			copy[union] = items
		}
	}
	return copy
}

func cloudflareSchemas(r *registry) {
	r.Schemas["CloudflareSSL"] = object(map[string]Schema{"method": enumeration("txt", "http", "email"), "type": scalar("string"), "status": scalar("string"), "settings": ref("JSONObject"), "validation_records": array(ref("JSONObject")), "validation_errors": array(ref("JSONObject")), "certificate_authority": scalar("string"), "wildcard": scalar("boolean")})
	r.Schemas["CloudflareSSL"]["additionalProperties"] = ref("JSONValue")
	r.Schemas["CloudflareHostname"] = object(map[string]Schema{"id": scalar("string"), "hostname": scalar("string"), "status": scalar("string"), "ssl": ref("CloudflareSSL"), "custom_origin_server": nullable(scalar("string")), "custom_metadata": dict(scalar("string")), "ownership_verification": object(map[string]Schema{"type": scalar("string"), "name": scalar("string"), "value": scalar("string")}), "ownership_verification_http": ref("JSONObject"), "created_at": ref("DateTime")})
	r.Schemas["CloudflareHostname"]["additionalProperties"] = ref("JSONValue")
	r.Schemas["CloudflareFallback"] = object(map[string]Schema{"origin": scalar("string"), "status": scalar("string")}, "origin")
	r.Schemas["CloudflareFallback"]["additionalProperties"] = ref("JSONValue")
	r.Schemas["CloudflareTunnel"] = object(map[string]Schema{"id": scalar("string"), "name": scalar("string"), "status": scalar("string"), "config_src": scalar("string"), "created_at": ref("DateTime"), "deleted_at": nullable(ref("DateTime")), "connections": array(ref("JSONObject")), "remote_config": scalar("boolean")})
	r.Schemas["CloudflareTunnel"]["additionalProperties"] = ref("JSONValue")
	r.Schemas["CloudflareRoute"] = object(map[string]Schema{"id": scalar("string"), "tunnel_id": scalar("string"), "network": scalar("string"), "hostname": scalar("string"), "comment": scalar("string"), "virtual_network_id": scalar("string"), "created_at": ref("DateTime"), "deleted_at": nullable(ref("DateTime"))})
	r.Schemas["CloudflareRoute"]["additionalProperties"] = ref("JSONValue")
	r.Schemas["IngressRule"] = object(map[string]Schema{"hostname": scalar("string"), "path": scalar("string"), "service": scalar("string"), "originRequest": ref("JSONObject")}, "service")
	r.Schemas["IngressRule"]["additionalProperties"] = ref("JSONValue")
	r.Schemas["IngressConfig"] = object(map[string]Schema{"ingress": array(ref("IngressRule")), "originRequest": ref("JSONObject"), "warp-routing": object(map[string]Schema{"enabled": scalar("boolean")})}, "ingress")
	r.Schemas["IngressConfig"]["additionalProperties"] = ref("JSONValue")
	r.Schemas["IngressResponse"] = object(map[string]Schema{"config": ref("IngressConfig"), "version": scalar("string"), "dns_synced": scalar("boolean")}, "config", "version")
	r.Schemas["CloudflareBatchItem"] = object(map[string]Schema{"target": scalar("string"), "success": scalar("boolean"), "error": scalar("string"), "result": ref("CloudflareHostname")}, "target", "success")
	r.Schemas["CloudflareBatchResult"] = object(map[string]Schema{"items": array(ref("CloudflareBatchItem")), "succeeded": scalar("integer"), "failed": scalar("integer")}, "items", "succeeded", "failed")
}

func settingsSchemas(r *registry) {
	r.Schemas["SiteSettings"] = object(map[string]Schema{"name": scalar("string"), "timezone": scalar("string"), "domain_expiry_days": scalar("string"), "certificate_renew_before_days": Schema{"type": "integer", "minimum": 1, "maximum": 365, "description": "Certificate expiry reminder threshold read by the worker; does not change per-certificate renewal policy."}, "notice": scalar("string")})
	r.Schemas["NetworkSettings"] = object(map[string]Schema{"proxy_url": described(scalar("string"), "Credential-bearing proxy URL; blank update preserves saved value and reads redact it."), "timeout_seconds": described(scalar("integer"), "Reserved persisted field; runtime providers currently apply their own timeouts.")})
	r.Schemas["SecuritySettings"] = object(map[string]Schema{"login_captcha": scalar("boolean")})
	r.Schemas["RetentionSettings"] = object(map[string]Schema{"audit_days": Schema{"type": "integer", "minimum": 7, "maximum": 3650}, "job_days": Schema{"type": "integer", "minimum": 7, "maximum": 3650}})
	r.Schemas["DeploymentSecuritySettings"] = object(map[string]Schema{"allowed_directories": array(scalar("string")), "remote_allowed_directories": array(scalar("string")), "allow_trusted_hooks": scalar("boolean"), "hook_timeout_seconds": described(scalar("integer"), "Reserved persisted field; trusted hooks currently use the implementation timeout.")})
	for _, name := range []string{"SiteSettings", "NetworkSettings", "SecuritySettings", "RetentionSettings", "DeploymentSecuritySettings"} {
		r.Schemas[name]["additionalProperties"] = ref("JSONValue")
	}
	r.Schemas["SettingsItems"] = object(map[string]Schema{"site": ref("SiteSettings"), "network": ref("NetworkSettings"), "security": ref("SecuritySettings"), "retention": ref("RetentionSettings"), "deployment_security": ref("DeploymentSecuritySettings")})
	r.Schemas["Settings"] = object(map[string]Schema{"items": ref("SettingsItems")}, "items")
}
