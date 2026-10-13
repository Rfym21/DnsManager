package httpapi

import (
	"database/sql"
	"encoding/json"
	"github.com/dns-manager/dnsmgr/server/internal/automation"
	"net/http"
	"strings"
	"time"

	certprovider "github.com/dns-manager/dnsmgr/server/internal/providers/cert"
	deployprovider "github.com/dns-manager/dnsmgr/server/internal/providers/deploy"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/redaction"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (a *API) dashboard(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	domains, err := a.Store.Domains(r.Context(), p)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	result := map[string]any{"domains": len(domains), "accounts": 0, "certificates": 0, "automations": 0, "pending_jobs": 0}
	if p.Admin() && p.AllowsScope("admin") {
		for key, query := range map[string]string{"accounts": "SELECT COUNT(*) FROM provider_accounts", "certificates": "SELECT COUNT(*) FROM objects WHERE kind='certificates'", "automations": "SELECT COUNT(*) FROM objects WHERE kind IN ('monitors','schedules','optimizations')", "pending_jobs": "SELECT COUNT(*) FROM jobs WHERE state IN ('queued','running')"} {
			var count int
			if err = a.Store.DB.QueryRowContext(r.Context(), query).Scan(&count); err != nil {
				a.internal(w, r, err)
				return
			}
			result[key] = count
		}
	}
	send(w, 200, result)
}
func (a *API) providers(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	catalog := []any{}
	for _, descriptor := range dns.Metadata() {
		raw, _ := json.Marshal(descriptor)
		var item map[string]any
		json.Unmarshal(raw, &item)
		markSecretFields(item)
		catalog = append(catalog, item)
	}
	for _, descriptor := range certprovider.Catalog {
		raw, _ := json.Marshal(descriptor)
		var item map[string]any
		json.Unmarshal(raw, &item)
		item["category"] = "cert"
		markSecretFields(item)
		catalog = append(catalog, item)
	}
	for _, descriptor := range deployprovider.Catalog {
		raw, _ := json.Marshal(descriptor)
		var item map[string]any
		json.Unmarshal(raw, &item)
		item["category"] = "deploy"
		markSecretFields(item)
		catalog = append(catalog, item)
	}
	send(w, 200, map[string]any{"items": catalog})
}
func markSecretFields(item map[string]any) {
	for _, collection := range []string{"fields", "target_fields"} {
		fields, _ := item[collection].([]any)
		for _, field := range fields {
			if value, ok := field.(map[string]any); ok {
				name, _ := value["name"].(string)
				if secretKey(name) {
					value["secret"] = true
				}
			}
		}
	}
}
func (a *API) accounts(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	items, err := a.Store.Accounts(r.Context())
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]any{"items": items})
}
func (a *API) accountDetail(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	account, err := a.Store.Account(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	raw, _ := json.Marshal(account)
	var response map[string]any
	json.Unmarshal(raw, &response)
	response["config"] = redaction.Value(account.Config)
	send(w, 200, response)
}
func (a *API) addAccount(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var req struct {
		Name     string            `json:"name"`
		Provider string            `json:"provider"`
		Config   map[string]string `json:"config"`
		Remark   string            `json:"remark"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Name == "" || len(req.Name) > 128 {
		a.fail(w, r, 400, "validation_failed", "需要账户名称")
		return
	}
	found := false
	for _, provider := range dns.Metadata() {
		if provider.ID == req.Provider && provider.Category == "dns" {
			found = true
		}
	}
	if !found {
		a.fail(w, r, 400, "unknown_provider", "未知 DNS 平台")
		return
	}
	account, err := a.Store.SaveAccount(r.Context(), store.Account{Name: req.Name, Provider: req.Provider, Config: req.Config, Remark: req.Remark}, true)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	a.Store.Audit(r.Context(), principal(r).User.ID, "account.create", "account", account.ID, "", middleware.GetReqID(r.Context()), map[string]string{"provider": account.Provider})
	send(w, 201, account)
}
func (a *API) updateAccount(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	account, err := a.Store.Account(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	var req struct {
		Name   string            `json:"name"`
		Config map[string]string `json:"config"`
		Remark string            `json:"remark"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Name == "" {
		a.fail(w, r, 400, "validation_failed", "需要账户名称")
		return
	}
	account.Name = req.Name
	account.Remark = req.Remark
	for key, value := range req.Config {
		if value != "" {
			account.Config[key] = value
		}
	}
	account, err = a.Store.SaveAccount(r.Context(), account, false)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, account)
}
func (a *API) deleteAccount(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var count int
	id := chi.URLParam(r, "id")
	if err := a.Store.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM domains WHERE account_id=?", id).Scan(&count); err != nil {
		a.internal(w, r, err)
		return
	}
	if count > 0 {
		a.fail(w, r, 409, "account_in_use", "请先移除此账户关联的域名")
		return
	}
	_, err := a.Store.DB.ExecContext(r.Context(), "DELETE FROM provider_accounts WHERE id=?", id)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (a *API) accountProvider(w http.ResponseWriter, r *http.Request) (store.Account, dns.Provider, bool) {
	account, err := a.Store.Account(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		a.internal(w, r, err)
		return account, nil, false
	}
	provider, err := a.DNSFactory(account.Provider, account.Config, "", "")
	if err != nil {
		a.fail(w, r, 422, "provider_unavailable", err.Error())
		return account, nil, false
	}
	return account, provider, true
}
func (a *API) verifyAccount(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	account, provider, ok := a.accountProvider(w, r)
	if !ok {
		return
	}
	status, message := "connected", ""
	if err := provider.Validate(r.Context()); err != nil {
		status = "error"
		message = safeProviderMessage(err)
	}
	_, err := a.Store.DB.ExecContext(r.Context(), "UPDATE provider_accounts SET status=?,last_error=?,updated_at=UTC_TIMESTAMP(6) WHERE id=?", status, message, account.ID)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]any{"status": status, "message": message})
}
func (a *API) providerDomains(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	_, provider, ok := a.accountProvider(w, r)
	if !ok {
		return
	}
	zones, err := provider.ListDomains(r.Context(), recordListOptions(r))
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, map[string]any{"items": zones.Rows, "pagination": map[string]any{"total": zones.Total}})
}
func (a *API) domains(w http.ResponseWriter, r *http.Request) {
	items, err := a.Store.Domains(r.Context(), principal(r))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	search := strings.ToLower(r.URL.Query().Get("search"))
	filtered := []store.Domain{}
	for _, domain := range items {
		domain.Permissions = []string{"dns:read"}
		if allowed, _ := a.Store.CanDomain(r.Context(), principal(r), domain.ID, "dns:write"); allowed {
			domain.Permissions = append(domain.Permissions, "dns:write")
		}
		if search == "" || strings.Contains(strings.ToLower(domain.Name+" "+domain.Remark), search) {
			filtered = append(filtered, domain)
		}
	}
	send(w, 200, map[string]any{"items": filtered, "pagination": map[string]int{"total": len(filtered)}})
}
func (a *API) addDomain(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var req struct {
		AccountID        string `json:"account_id"`
		ProviderDomainID string `json:"provider_domain_id"`
		Name             string `json:"name"`
		Category         string `json:"category"`
		Remark           string `json:"remark"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	ascii, err := dns.CanonicalName(req.Name)
	if err != nil || req.ProviderDomainID == "" {
		a.fail(w, r, 400, "invalid_domain", "域名或平台域名 ID 不正确")
		return
	}
	if _, err = a.Store.Account(r.Context(), req.AccountID); err != nil {
		a.internal(w, r, err)
		return
	}
	d, err := a.Store.AddDomain(r.Context(), store.Domain{AccountID: req.AccountID, ProviderDomainID: req.ProviderDomainID, Name: req.Name, ASCIIName: ascii, Category: req.Category, Remark: req.Remark})
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 201, d)
}
func (a *API) domain(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !a.authorizeDomain(w, r, id, "dns:read") {
		return
	}
	d, err := a.Store.Domain(r.Context(), id)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	d.Permissions = []string{"dns:read"}
	if allowed, _ := a.Store.CanDomain(r.Context(), principal(r), id, "dns:write"); allowed {
		d.Permissions = append(d.Permissions, "dns:write")
	}
	send(w, 200, d)
}
func (a *API) updateDomain(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var req struct {
		Category   string `json:"category"`
		Remark     string `json:"remark"`
		Quicklogin bool   `json:"quicklogin_enabled"`
		Hidden     bool   `json:"hidden"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	_, err := a.Store.DB.ExecContext(r.Context(), "UPDATE domains SET category=?,remark=?,quicklogin_enabled=?,hidden=?,updated_at=UTC_TIMESTAMP(6) WHERE id=?", req.Category, req.Remark, req.Quicklogin, req.Hidden, chi.URLParam(r, "id"))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (a *API) deleteDomain(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	tx, err := a.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM objects WHERE domain_id=?", id).Scan(&count); err != nil {
		a.internal(w, r, err)
		return
	}
	if count > 0 {
		a.fail(w, r, 409, "domain_in_use", "请先移除关联的任务与证书")
		return
	}
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM domain_grants WHERE domain_id=?", id); err == nil {
		_, err = tx.ExecContext(r.Context(), "DELETE FROM domains WHERE id=?", id)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (a *API) domainProvider(w http.ResponseWriter, r *http.Request, action string) (store.Domain, dns.Provider, bool) {
	id := chi.URLParam(r, "id")
	if !a.authorizeDomain(w, r, id, action) {
		return store.Domain{}, nil, false
	}
	domain, err := a.Store.Domain(r.Context(), id)
	if err != nil {
		a.internal(w, r, err)
		return domain, nil, false
	}
	account, err := a.Store.Account(r.Context(), domain.AccountID)
	if err != nil {
		a.internal(w, r, err)
		return domain, nil, false
	}
	provider, err := a.DNSFactory(account.Provider, account.Config, domain.ProviderDomainID, domain.ASCIIName)
	if err != nil {
		a.fail(w, r, 422, "provider_unavailable", err.Error())
		return domain, nil, false
	}
	return domain, provider, true
}
func (a *API) records(w http.ResponseWriter, r *http.Request) {
	_, provider, ok := a.domainProvider(w, r, "dns:read")
	if !ok {
		return
	}
	records, err := provider.ListRecords(r.Context(), recordListOptions(r))
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	for i := range records.Rows {
		records.Rows[i].Version = recordVersion(records.Rows[i])
	}
	send(w, 200, map[string]any{"items": records.Rows, "pagination": map[string]any{"total": records.Total}, "capabilities": provider.Descriptor().Capabilities, "fetched_at": time.Now().UTC()})
}
func (a *API) createRecord(w http.ResponseWriter, r *http.Request) { a.writeRecord(w, r, true) }
func (a *API) updateRecord(w http.ResponseWriter, r *http.Request) { a.writeRecord(w, r, false) }
func (a *API) writeRecord(w http.ResponseWriter, r *http.Request, create bool) {
	d, provider, ok := a.domainProvider(w, r, "dns:write")
	if !ok {
		return
	}
	var record dns.Record
	if !a.decode(w, r, &record) {
		return
	}
	record.Type = strings.ToUpper(record.Type)
	if record.TTL == 0 {
		record.TTL = 1
	}
	if err := dns.ValidateRecord(record, d.ASCIIName); err != nil {
		a.fail(w, r, 400, "validation_failed", err.Error())
		return
	}
	var result dns.Record
	var err error
	action := "record.create"
	if create {
		result, err = provider.CreateRecord(r.Context(), record)
	} else {
		record.ID = chi.URLParam(r, "record")
		if record.Version != "" {
			current, e := provider.GetRecord(r.Context(), record.ID)
			if e != nil {
				a.providerError(w, r, e)
				return
			}
			if recordVersion(current) != record.Version {
				a.fail(w, r, 409, "conflict", "记录已变化，请重新读取后提交")
				return
			}
		}
		result, err = provider.UpdateRecord(r.Context(), record.ID, record)
		action = "record.update"
	}
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	if err = a.Store.Audit(r.Context(), principal(r).User.ID, action, "record", result.ID, d.ID, middleware.GetReqID(r.Context()), map[string]string{"name": result.Name, "type": result.Type}); err != nil {
		a.fail(w, r, 500, "audit_failed_after_write", "平台已接受变更，但审计保存失败，请刷新核对记录后再操作")
		return
	}
	send(w, 200, result)
}
func (a *API) deleteRecord(w http.ResponseWriter, r *http.Request) {
	d, provider, ok := a.domainProvider(w, r, "dns:write")
	if !ok {
		return
	}
	id := chi.URLParam(r, "record")
	if err := provider.DeleteRecord(r.Context(), id); err != nil {
		a.providerError(w, r, err)
		return
	}
	if err := a.Store.Audit(r.Context(), principal(r).User.ID, "record.delete", "record", id, d.ID, middleware.GetReqID(r.Context()), map[string]bool{"deleted": true}); err != nil {
		a.fail(w, r, 500, "audit_failed_after_write", "平台已删除记录，但审计保存失败，请刷新核对")
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}

var objectKinds = map[string]bool{"certificates": true, "issuer_accounts": true, "deploy_accounts": true, "deployments": true, "monitors": true, "schedules": true, "optimizations": true, "notification_channels": true, "delegations": true, "aliases": true, "categories": true, "proxy_profiles": true}

func (a *API) validKind(w http.ResponseWriter, r *http.Request) bool {
	if route := chi.RouteContext(r.Context()); route != nil {
		for i, key := range route.URLParams.Keys {
			if key == "kind" {
				route.URLParams.Values[i] = canonicalKind(route.URLParams.Values[i])
			}
		}
	}
	if !objectKinds[chi.URLParam(r, "kind")] {
		a.fail(w, r, 404, "not_found", "资源类型不存在")
		return false
	}
	return true
}
func (a *API) objects(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) || !a.validKind(w, r) {
		return
	}
	items, err := a.Store.Objects(r.Context(), chi.URLParam(r, "kind"))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	for i := range items {
		items[i].Data = redactJSON(items[i].Data)
	}
	send(w, 200, map[string]any{"items": items})
}
func (a *API) object(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) || !a.validKind(w, r) {
		return
	}
	o, err := a.Store.Object(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	if o.Kind != chi.URLParam(r, "kind") {
		a.fail(w, r, 404, "not_found", "资源不存在")
		return
	}
	o.Data = redactJSON(o.Data)
	send(w, 200, o)
}
func (a *API) createObject(w http.ResponseWriter, r *http.Request) { a.writeObject(w, r, true) }
func (a *API) updateObject(w http.ResponseWriter, r *http.Request) { a.writeObject(w, r, false) }
func (a *API) writeObject(w http.ResponseWriter, r *http.Request, create bool) {
	if !a.admin(w, r) || !a.validKind(w, r) {
		return
	}
	var req struct {
		Name     string          `json:"name"`
		DomainID string          `json:"domain_id"`
		Data     json.RawMessage `json:"data"`
		Active   bool            `json:"active"`
		Version  int64           `json:"version"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Name == "" || len(req.Name) > 255 || !json.Valid(req.Data) {
		a.fail(w, r, 400, "validation_failed", "名称与配置不能为空")
		return
	}
	o := store.Object{Kind: chi.URLParam(r, "kind"), Name: req.Name, DomainID: req.DomainID, OwnerID: principal(r).User.ID, Data: req.Data, Active: req.Active, Version: req.Version}
	if !create {
		old, err := a.Store.Object(r.Context(), chi.URLParam(r, "id"))
		if err != nil {
			a.internal(w, r, err)
			return
		}
		if old.Kind != o.Kind {
			a.fail(w, r, 404, "not_found", "资源不存在")
			return
		}
		o.ID = old.ID
		o.OwnerID = old.OwnerID
		o.DomainID = old.DomainID
		o.Data = mergeSecrets(old.Data, o.Data)
		o.Data, err = configurationData(o.Kind, old.Data, o.Data)
		if err != nil {
			a.fail(w, r, 400, "validation_failed", err.Error())
			return
		}
	}
	if create {
		var err error
		o.Data, err = configurationData(o.Kind, nil, o.Data)
		if err != nil {
			a.fail(w, r, 400, "validation_failed", err.Error())
			return
		}
	}
	if o.DomainID != "" {
		if _, err := a.Store.Domain(r.Context(), o.DomainID); err != nil {
			a.internal(w, r, err)
			return
		}
	}
	if err := a.validateReferences(r.Context(), o); err != nil {
		a.fail(w, r, 400, "validation_failed", err.Error())
		return
	}
	if err := validateObject(o); err != nil {
		a.fail(w, r, 400, "validation_failed", err.Error())
		return
	}
	if o.Kind == "certificates" {
		var data automation.CertificateData
		json.Unmarshal(o.Data, &data)
		if data.AccountID == "" {
			result, err := certprovider.ParseResult(data.Fullchain, data.PrivateKey)
			if err != nil {
				a.fail(w, r, 400, "validation_failed", err.Error())
				return
			}
			data.Status = "issued"
			data.Fingerprint = result.Fingerprint
			data.NotBefore = result.NotBefore
			data.NotAfter = result.NotAfter
			data.Issuer = result.Issuer
			data.AutoRenew = false
			o.Data, _ = json.Marshal(data)
		}
	}
	saved, err := a.Store.SaveObject(r.Context(), o, create)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	saved.Data = redactJSON(saved.Data)
	send(w, 200, saved)
}
func (a *API) deleteObject(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) || !a.validKind(w, r) {
		return
	}
	inUse, err := a.objectInUse(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	if inUse {
		a.fail(w, r, 409, "resource_in_use", "请先处理关联资源与未完成任务")
		return
	}
	_, err = a.Store.DB.ExecContext(r.Context(), "DELETE FROM objects WHERE id=? AND kind=?", chi.URLParam(r, "id"), chi.URLParam(r, "kind"))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func secretKey(key string) bool {
	return effectiveSecretKey(key)
}
func redactJSON(raw json.RawMessage) json.RawMessage {
	return redaction.JSON(raw)
}
func mergeSecrets(old, new json.RawMessage) json.RawMessage {
	var before, after map[string]any
	if json.Unmarshal(old, &before) != nil || json.Unmarshal(new, &after) != nil {
		return new
	}
	var merge func(map[string]any, map[string]any)
	merge = func(a, b map[string]any) {
		for key, value := range a {
			if secretKey(key) {
				if next, exists := b[key]; !exists || next == "" {
					b[key] = value
				}
			} else if left, ok := value.(map[string]any); ok {
				if right, ok := b[key].(map[string]any); ok {
					merge(left, right)
				}
			}
		}
	}
	merge(before, after)
	out, _ := json.Marshal(after)
	return out
}
func (a *API) audit(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.DomainID != "" || (p.Token && !p.AllowsScope("admin")) {
		a.fail(w, r, 403, "forbidden", "此会话不能读取审计日志")
		return
	}
	query := "SELECT id,actor_id,action,resource_type,resource_id,domain_id,request_id,detail,created_at FROM audit_events"
	args := []any{}
	filters := []string{}
	if !p.Admin() {
		filters = append(filters, "actor_id=? AND (domain_id IS NULL OR EXISTS (SELECT 1 FROM domain_grants g WHERE g.user_id=? AND g.domain_id=audit_events.domain_id))")
		args = append(args, p.User.ID, p.User.ID)
	}
	if domainID := r.URL.Query().Get("domain_id"); domainID != "" {
		if !a.authorizeDomain(w, r, domainID, "dns:read") {
			return
		}
		filters = append(filters, "domain_id=?")
		args = append(args, domainID)
	}
	if len(filters) > 0 {
		query += " WHERE " + strings.Join(filters, " AND ")
	}
	query += " ORDER BY id DESC LIMIT 200"
	rows, err := a.Store.DB.QueryContext(r.Context(), query, args...)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int64
		var actor, action, kind, resource, request string
		var domain *string
		var detail []byte
		var created any
		if err = rows.Scan(&id, &actor, &action, &kind, &resource, &domain, &request, &detail, &created); err != nil {
			a.internal(w, r, err)
			return
		}
		items = append(items, map[string]any{"id": id, "actor_id": actor, "action": action, "resource_type": kind, "resource_id": resource, "domain_id": domain, "request_id": request, "detail": redactJSON(detail), "created_at": created})
	}
	send(w, 200, map[string]any{"items": items})
}
func (a *API) settings(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	rows, err := a.Store.DB.QueryContext(r.Context(), "SELECT name,ciphertext FROM settings")
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer rows.Close()
	values := map[string]json.RawMessage{}
	for rows.Next() {
		var name, enc string
		if err = rows.Scan(&name, &enc); err != nil {
			a.internal(w, r, err)
			return
		}
		if !editableSetting(name) {
			continue
		}
		raw, err := a.Store.Box.Open("setting:"+name, enc)
		if err != nil {
			a.internal(w, r, err)
			return
		}
		if name == "network" {
			var network map[string]any
			if json.Unmarshal(raw, &network) == nil {
				network["proxy_url"] = ""
				raw, _ = json.Marshal(network)
			}
		}
		values[name] = redactJSON(raw)
	}
	send(w, 200, map[string]any{"items": values})
}
func editableSetting(name string) bool {
	switch name {
	case "site", "network", "deployment_security", "security", "retention":
		return true
	}
	return false
}
func (a *API) saveSettings(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var payload struct {
		Items map[string]json.RawMessage `json:"items"`
	}
	if !a.decode(w, r, &payload) {
		return
	}
	// Validate the whole request before any setting can be committed.
	for name, value := range payload.Items {
		if !editableSetting(name) {
			a.fail(w, r, 403, "protected_setting", "内部设置只能通过专用接口或命令修改")
			return
		}
		if err := validateSetting(name, value); err != nil {
			a.fail(w, r, 400, "validation_failed", err.Error())
			return
		}
	}
	tx, err := a.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer tx.Rollback()
	for name, value := range payload.Items {
		var ciphertext string
		err = tx.QueryRowContext(r.Context(), "SELECT ciphertext FROM settings WHERE name=? FOR UPDATE", name).Scan(&ciphertext)
		if err != nil && err != sql.ErrNoRows {
			a.internal(w, r, err)
			return
		}
		if err == nil {
			before, e := a.Store.Box.Open("setting:"+name, ciphertext)
			if e != nil {
				a.internal(w, r, e)
				return
			}
			var old, next map[string]json.RawMessage
			if json.Unmarshal(before, &old) != nil || json.Unmarshal(value, &next) != nil {
				a.fail(w, r, 400, "validation_failed", "设置必须为 JSON 对象")
				return
			}
			for k, v := range next {
				old[k] = v
			}
			value, _ = json.Marshal(old)
			value = mergeSecrets(before, value)
			if name == "network" {
				var left, right map[string]any
				json.Unmarshal(before, &left)
				json.Unmarshal(value, &right)
				if right["proxy_url"] == "" {
					right["proxy_url"] = left["proxy_url"]
					value, _ = json.Marshal(right)
				}
			}
		}
		enc, e := a.Store.Box.Seal("setting:"+name, value)
		if e != nil {
			a.internal(w, r, e)
			return
		}
		if _, err = tx.ExecContext(r.Context(), "INSERT INTO settings(name,ciphertext,updated_at) VALUES(?,?,UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE ciphertext=VALUES(ciphertext),version=version+1,updated_at=UTC_TIMESTAMP(6)", name, enc); err != nil {
			a.internal(w, r, err)
			return
		}
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor_id,action,resource_type,resource_id,request_id,detail,created_at) VALUES(?,'settings.update','settings','instance','',JSON_OBJECT(),UTC_TIMESTAMP(6))", principal(r).User.ID); err != nil {
		a.internal(w, r, err)
		return
	}
	if err = tx.Commit(); err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
