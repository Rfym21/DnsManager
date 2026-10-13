package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/go-chi/chi/v5"
)

type cfBatchItem struct {
	Target  string          `json:"target"`
	Success bool            `json:"success"`
	Error   string          `json:"error,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
}

func (a *API) cfHostnamesBatch(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.cfDomain(w, r)
	if !ok {
		return
	}
	var req struct {
		Action    string         `json:"action"`
		Hostnames []string       `json:"hostnames"`
		IDs       []string       `json:"ids"`
		Origin    *string        `json:"custom_origin_server"`
		SSL       map[string]any `json:"ssl"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	targets := req.IDs
	if req.Action == "add" {
		targets = req.Hostnames
	}
	if len(targets) == 0 || len(targets) > 200 {
		a.fail(w, r, 400, "invalid_batch", "批量操作须包含1至200项")
		return
	}
	if req.Action != "add" && req.Action != "update" && req.Action != "delete" {
		a.fail(w, r, 400, "invalid_action", "批量操作须为add/update/delete")
		return
	}
	if req.SSL != nil {
		if err := cfValidateSSL(req.SSL); err != nil {
			a.fail(w, r, 400, "invalid_ssl", err.Error())
			return
		}
	}
	if req.Origin != nil && *req.Origin != "" {
		origin, err := cfNormalizeHostname(*req.Origin, false)
		if err != nil {
			a.fail(w, r, 400, "invalid_origin", err.Error())
			return
		}
		req.Origin = &origin
	}
	path := "/zones/" + url.PathEscape(d.ProviderDomainID) + "/custom_hostnames"
	items := []cfBatchItem{}
	success := 0
	seen := map[string]bool{}
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if seen[target] {
			continue
		}
		seen[target] = true
		item := cfBatchItem{Target: target}
		var result json.RawMessage
		var err error
		if req.Action == "add" {
			name, e := cfNormalizeHostname(target, false)
			err = e
			if err == nil {
				ssl := req.SSL
				if ssl == nil {
					ssl = map[string]any{"method": "txt", "type": "dv", "settings": map[string]any{"min_tls_version": "1.2"}}
				}
				body := map[string]any{"hostname": name, "ssl": ssl}
				if req.Origin != nil && *req.Origin != "" {
					body["custom_origin_server"] = *req.Origin
				}
				result, err = c.call(r, http.MethodPost, path, body)
			}
		} else {
			itemPath := path + "/" + url.PathEscape(target)
			if target == "" {
				err = errors.New("主机名ID不能为空")
			} else if req.Action == "delete" {
				result, err = c.call(r, http.MethodDelete, itemPath, nil)
			} else {
				var current json.RawMessage
				current, err = c.call(r, http.MethodGet, itemPath, nil)
				if err == nil {
					var value map[string]any
					value, err = cfParseMap(current)
					if err == nil {
						body := map[string]any{}
						if req.Origin != nil {
							if *req.Origin == "" {
								body["custom_origin_server"] = nil
							} else {
								body["custom_origin_server"] = *req.Origin
							}
						}
						if req.SSL != nil {
							body["ssl"] = cfMergeSSL(cfObject(value["ssl"]), req.SSL)
						}
						if len(body) == 0 {
							err = errors.New("请指定要修改的源站或SSL字段")
						} else {
							result, err = c.call(r, http.MethodPatch, itemPath, body)
						}
					}
				}
			}
		}
		if err == nil {
			err = a.cfAudit(r, "hostname.batch."+req.Action, target, d.ID, nil)
		}
		if err != nil {
			item.Error = safeProviderMessage(err)
		} else {
			item.Success = true
			item.Result = result
			success++
		}
		items = append(items, item)
	}
	send(w, 200, map[string]any{"items": items, "succeeded": success, "failed": len(items) - success})
}

type cfVerification struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

func cfVerificationRecords(host map[string]any) []cfVerification {
	items := []cfVerification{}
	seen := map[string]bool{}
	add := func(name, value, kind string) {
		if name == "" || value == "" {
			return
		}
		key := name + "\x00" + value
		if !seen[key] {
			items = append(items, cfVerification{name, value, kind})
			seen[key] = true
		}
	}
	ownership := cfObject(host["ownership_verification"])
	add(cfString(ownership["name"]), cfString(ownership["value"]), "TXT")
	for _, raw := range cfArray(cfObject(host["ssl"])["validation_records"]) {
		record := cfObject(raw)
		add(cfString(record["txt_name"]), cfString(record["txt_value"]), "TXT")
	}
	return items
}
func (a *API) cfHostnameTXT(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.cfDomain(w, r)
	if !ok {
		return
	}
	var req struct {
		DomainID string `json:"domain_id"`
		Line     string `json:"line"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	raw, err := c.call(r, http.MethodGet, "/zones/"+url.PathEscape(d.ProviderDomainID)+"/custom_hostnames/"+url.PathEscape(chi.URLParam(r, "hostname")), nil)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	host, err := cfParseMap(raw)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	records := cfVerificationRecords(host)
	if len(records) == 0 {
		a.fail(w, r, 422, "verification_not_ready", "此主机名暂未返回TXT验证记录")
		return
	}
	result, err := a.cfWriteVerification(r, req.DomainID, req.Line, records)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, result)
}
func (a *API) cfDCVDelegate(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.cfDomain(w, r)
	if !ok {
		return
	}
	var req struct {
		DomainID  string   `json:"domain_id"`
		Hostnames []string `json:"hostnames"`
		Line      string   `json:"line"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if len(req.Hostnames) == 0 || len(req.Hostnames) > 200 {
		a.fail(w, r, 400, "invalid_hostnames", "请输入1至200个委派域名")
		return
	}
	raw, err := c.call(r, http.MethodGet, "/zones/"+url.PathEscape(d.ProviderDomainID)+"/dcv_delegation/uuid", nil)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	value, err := cfParseMap(raw)
	if err != nil || cfString(value["uuid"]) == "" {
		a.fail(w, r, 422, "uuid_unavailable", "Cloudflare暂未返回DCV UUID")
		return
	}
	records := []cfVerification{}
	for _, hostname := range req.Hostnames {
		name, e := cfNormalizeHostname(strings.TrimPrefix(hostname, "*."), false)
		if e != nil {
			a.fail(w, r, 400, "invalid_hostname", e.Error())
			return
		}
		records = append(records, cfVerification{Name: "_acme-challenge." + name, Type: "CNAME", Value: cfString(value["uuid"]) + ".dcv.cloudflare.com"})
	}
	result, err := a.cfWriteVerification(r, req.DomainID, req.Line, records)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, result)
}
func (a *API) cfWriteVerification(r *http.Request, domainID, line string, records []cfVerification) (map[string]any, error) {
	target, err := a.Store.Domain(r.Context(), domainID)
	if err != nil {
		return nil, err
	}
	account, err := a.Store.Account(r.Context(), target.AccountID)
	if err != nil {
		return nil, err
	}
	// The outer middleware locks the source account; lock a separate target account as well.
	sourceID := chi.URLParam(r, "id")
	source, err := a.Store.Domain(r.Context(), sourceID)
	if err != nil {
		return nil, err
	}
	if target.AccountID != source.AccountID {
		release, e := a.Store.LockResources(r.Context(), []string{"dns-account:" + target.AccountID})
		if e != nil {
			return nil, e
		}
		defer release()
	}
	client, err := a.Store.HTTPClient(r.Context(), account.Config, 25*time.Second)
	if err != nil {
		return nil, err
	}
	provider, err := dns.NewWithOptions(account.Provider, account.Config, target.ProviderDomainID, target.ASCIIName, dns.FactoryOptions{Client: client})
	if err != nil {
		return nil, err
	}
	prepared := []dns.Record{}
	for _, record := range records {
		name, e := cfNormalizeHostname(record.Name, true)
		if e != nil {
			return nil, e
		}
		relative, e := cfRecordName(target, name)
		if e != nil {
			return nil, e
		}
		prepared = append(prepared, dns.Record{Name: relative, Type: record.Type, Value: record.Value, TTL: 600, Enabled: true, Line: line})
	}
	if line == "" {
		lines, e := provider.Lines(r.Context())
		if e != nil {
			return nil, e
		}
		if len(lines) > 0 {
			for i := range prepared {
				prepared[i].Line = lines[0].ID
			}
		}
	}
	items := []cfBatchItem{}
	success := 0
	for _, record := range prepared {
		item := cfBatchItem{Target: record.Name}
		err := cfEnsureVerification(r, provider, record)
		if err == nil {
			err = a.cfAudit(r, "verification.write", record.Name, target.ID, map[string]string{"type": record.Type})
		}
		if err != nil {
			item.Error = safeProviderMessage(err)
		} else {
			item.Success = true
			success++
		}
		items = append(items, item)
	}
	return map[string]any{"items": items, "succeeded": success, "failed": len(items) - success}, nil
}
func cfEnsureVerification(r *http.Request, provider dns.Provider, record dns.Record) error {
	listed := 0
	for page := 1; page <= 200; page++ {
		rows, err := provider.ListRecords(r.Context(), dns.ListOptions{Name: record.Name, Page: page, PageSize: 500})
		if err != nil {
			return err
		}
		for _, existing := range rows.Rows {
			if !strings.EqualFold(strings.TrimSuffix(existing.Name, "."), strings.TrimSuffix(record.Name, ".")) {
				continue
			}
			equalValue := existing.Value == record.Value
			if record.Type == "CNAME" {
				equalValue = strings.EqualFold(strings.TrimSuffix(existing.Value, "."), strings.TrimSuffix(record.Value, "."))
			}
			for _, value := range existing.Values {
				if value == record.Value {
					equalValue = true
				}
			}
			if strings.EqualFold(existing.Type, record.Type) && equalValue && existing.Line == record.Line {
				if !existing.Enabled {
					return errors.New("相同验证记录已存在但未启用，请先确认并启用")
				}
				return nil
			}
			if strings.EqualFold(existing.Type, "CNAME") || record.Type == "CNAME" {
				return errors.New("验证主机已存在其他记录，请手动确认后修改")
			}
		}
		listed += len(rows.Rows)
		if rows.Total > 0 && listed >= rows.Total || rows.Total == 0 && len(rows.Rows) < 500 {
			_, err = provider.CreateRecord(r.Context(), record)
			return err
		}
	}
	return errors.New("验证记录查询超过分页上限，未写入新记录")
}
