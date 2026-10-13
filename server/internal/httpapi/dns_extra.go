package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/go-chi/chi/v5"
)

func recordListOptions(r *http.Request) dns.ListOptions {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("page_size"))
	if size == 0 {
		size = 50
	}
	o := dns.ListOptions{Page: page, PageSize: size, Keyword: q.Get("search"), Name: q.Get("name"), Value: q.Get("value"), Type: q.Get("type"), Line: q.Get("line"), Sort: q.Get("sort"), Desc: q.Get("order") == "desc", GroupID: q.Get("group_id")}
	if q.Get("enabled") != "" {
		value := q.Get("enabled") == "true" || q.Get("enabled") == "1"
		o.Enabled = &value
	}
	return o
}
func recordVersion(r dns.Record) string {
	r.Version = ""
	b, _ := json.Marshal(r)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}
func (a *API) providerError(w http.ResponseWriter, r *http.Request, err error) {
	var remote *dns.RemoteError
	if errors.As(err, &remote) && remote.UnknownResult {
		a.fail(w, r, 409, "result_unknown", "平台操作结果尚未确认，请刷新记录核对后再操作")
		return
	}
	if errors.Is(err, dns.ErrNotFound) {
		a.fail(w, r, 404, "not_found", "记录不存在")
		return
	}
	if errors.Is(err, dns.ErrConflict) {
		a.fail(w, r, 409, "conflict", "记录已变化，请重新读取")
		return
	}
	if errors.Is(err, dns.ErrCapability) {
		a.fail(w, r, 422, "unsupported_capability", "该平台不支持此操作")
		return
	}
	a.fail(w, r, 502, "provider_error", safeProviderMessage(err))
}
func safeProviderMessage(err error) string {
	// Do not echo URL query strings or remote bodies that may contain credentials.
	message := err.Error()
	if strings.Contains(message, "http://") || strings.Contains(message, "https://") {
		return "平台连接或请求失败，请检查账户配置和连接"
	}
	if len(message) > 500 {
		message = message[:500]
	}
	return message
}
func (a *API) recordStatus(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.domainProvider(w, r, "dns:write")
	if !ok {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if err := p.SetStatus(r.Context(), chi.URLParam(r, "record"), req.Enabled); err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (a *API) recordRemark(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.domainProvider(w, r, "dns:write")
	if !ok {
		return
	}
	var req struct {
		Remark string `json:"remark"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if err := p.SetRemark(r.Context(), chi.URLParam(r, "record"), req.Remark); err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (a *API) recordCapabilities(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.domainProvider(w, r, "dns:read")
	if !ok {
		return
	}
	lines, err := p.Lines(r.Context())
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	ttl, err := p.MinTTL(r.Context())
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, map[string]any{"capabilities": p.Descriptor().Capabilities, "lines": lines, "min_ttl": ttl, "proxy": p.Descriptor().ID == "cloudflare"})
}
func (a *API) recordGroups(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.domainProvider(w, r, "dns:read")
	if !ok {
		return
	}
	groups, ok := p.(dns.GroupProvider)
	if !ok {
		a.providerError(w, r, dns.ErrCapability)
		return
	}
	values, err := groups.Groups(r.Context())
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, map[string]any{"items": values})
}
func (a *API) setRecordGroup(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.domainProvider(w, r, "dns:write")
	if !ok {
		return
	}
	groups, ok := p.(dns.GroupProvider)
	if !ok {
		a.providerError(w, r, dns.ErrCapability)
		return
	}
	var req struct {
		RecordIDs []string `json:"record_ids"`
		GroupID   string   `json:"group_id"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if err := groups.SetGroup(r.Context(), req.RecordIDs, req.GroupID); err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (a *API) recordLogs(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.domainProvider(w, r, "dns:read")
	if !ok {
		return
	}
	logs, ok := p.(dns.LogProvider)
	if !ok {
		a.providerError(w, r, dns.ErrCapability)
		return
	}
	items, total, err := logs.Logs(r.Context(), recordListOptions(r))
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, map[string]any{"items": items, "pagination": map[string]int{"total": total}})
}
func (a *API) recordWeights(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.domainProvider(w, r, "dns:read")
	if !ok {
		return
	}
	weight, ok := p.(dns.WeightProvider)
	if !ok {
		a.providerError(w, r, dns.ErrCapability)
		return
	}
	items, total, err := weight.WeightGroups(r.Context(), recordListOptions(r))
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, map[string]any{"items": items, "pagination": map[string]int{"total": total}})
}
func (a *API) setRecordWeight(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.domainProvider(w, r, "dns:write")
	if !ok {
		return
	}
	weight, ok := p.(dns.WeightProvider)
	if !ok {
		a.providerError(w, r, dns.ErrCapability)
		return
	}
	var req struct {
		RecordID string `json:"record_id"`
		Weight   int    `json:"weight"`
		Name     string `json:"name"`
		Type     string `json:"type"`
		Line     string `json:"line"`
		Enabled  *bool  `json:"enabled"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	var err error
	if req.Enabled != nil {
		err = weight.SetWeightGroup(r.Context(), req.Name, req.Type, req.Line, *req.Enabled)
	} else {
		err = weight.SetWeight(r.Context(), req.RecordID, req.Weight)
	}
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (a *API) providerAliases(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.domainProvider(w, r, "dns:read")
	if !ok {
		return
	}
	alias, ok := p.(dns.AliasProvider)
	if !ok {
		a.providerError(w, r, dns.ErrCapability)
		return
	}
	items, err := alias.Aliases(r.Context())
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, map[string]any{"items": items})
}
func (a *API) writeProviderAlias(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.domainProvider(w, r, "dns:write")
	if !ok {
		return
	}
	alias, ok := p.(dns.AliasProvider)
	if !ok {
		a.providerError(w, r, dns.ErrCapability)
		return
	}
	var err error
	if r.Method == "DELETE" {
		err = alias.DeleteAlias(r.Context(), chi.URLParam(r, "alias"))
	} else {
		var req struct {
			Name string `json:"name"`
		}
		if !a.decode(w, r, &req) {
			return
		}
		err = alias.CreateAlias(r.Context(), req.Name)
	}
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
