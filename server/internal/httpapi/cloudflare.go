package httpapi

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/go-chi/chi/v5"
)

type cfClient struct {
	client    *http.Client
	config    map[string]string
	accountID string
}

type cfEnvelope struct {
	Success    bool            `json:"success"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		TotalCount int `json:"total_count"`
		TotalPages int `json:"total_pages"`
		Page       int `json:"page"`
	} `json:"result_info"`
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}
type cfError struct {
	Status, Code int
	Message      string
}

func (e *cfError) Error() string { return fmt.Sprintf("Cloudflare %d: %s", e.Code, e.Message) }
func (c cfClient) raw(r *http.Request, method, path string, body any) (cfEnvelope, error) {
	var result cfEnvelope
	var data io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return result, err
		}
		data = bytes.NewReader(raw)
	}
	endpoint := "https://api.cloudflare.com/client/v4"
	if c.config["api_url"] != "" {
		endpoint = strings.TrimRight(c.config["api_url"], "/")
	}
	origin, err := url.Parse(endpoint)
	if err != nil || origin.Host == "" || (origin.Scheme != "https" && origin.Scheme != "http") || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" {
		return result, errors.New("Cloudflare API地址无效")
	}
	req, err := http.NewRequestWithContext(r.Context(), method, endpoint+path, data)
	if err != nil {
		return result, errors.New("Cloudflare请求无效")
	}
	token := c.config["api_token"]
	if c.config["auth"] == "1" {
		token = c.config["apikey"]
	}
	if token == "" {
		token = c.config["token"]
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		key := c.config["api_key"]
		if key == "" {
			key = c.config["apikey"]
		}
		if key == "" {
			key = c.config["key"]
		}
		if key == "" || c.config["email"] == "" {
			return result, errors.New("Cloudflare API凭据不完整")
		}
		req.Header.Set("X-Auth-Email", c.config["email"])
		req.Header.Set("X-Auth-Key", key)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := c.client
	if client == nil {
		client = &http.Client{Timeout: 25 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		return result, errors.New("Cloudflare连接失败")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, (8<<20)+1))
	if err != nil || len(raw) > 8<<20 {
		return result, errors.New("Cloudflare响应超过限制或读取失败")
	}
	if json.Unmarshal(raw, &result) != nil {
		return result, errors.New("Cloudflare响应格式不正确")
	}
	if res.StatusCode/100 != 2 || !result.Success {
		e := &cfError{Status: res.StatusCode, Message: "请求失败"}
		if len(result.Errors) > 0 {
			e.Code = result.Errors[0].Code
			e.Message = result.Errors[0].Message
		}
		for _, secret := range c.config {
			if len(secret) > 3 {
				e.Message = strings.ReplaceAll(e.Message, secret, "[redacted]")
			}
		}
		if len(e.Message) > 500 {
			e.Message = e.Message[:500]
		}
		return result, e
	}
	return result, nil
}
func (c cfClient) call(r *http.Request, method, path string, body any) (json.RawMessage, error) {
	value, err := c.raw(r, method, path, body)
	return value.Result, err
}
func (c cfClient) list(r *http.Request, path string, query url.Values) ([]map[string]any, error) {
	if query == nil {
		query = url.Values{}
	}
	items := []map[string]any{}
	for page := 1; page <= 200; page++ {
		query.Set("page", strconv.Itoa(page))
		query.Set("per_page", "100")
		value, err := c.raw(r, http.MethodGet, path+"?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var rows []map[string]any
		decoder := json.NewDecoder(bytes.NewReader(value.Result))
		decoder.UseNumber()
		if decoder.Decode(&rows) != nil {
			return nil, errors.New("Cloudflare列表格式不正确")
		}
		items = append(items, rows...)
		if value.ResultInfo.TotalPages > 0 && page >= value.ResultInfo.TotalPages || value.ResultInfo.TotalPages == 0 && len(rows) < 100 {
			return items, nil
		}
	}
	return nil, errors.New("Cloudflare列表超过分页上限")
}
func (a *API) cfAccount(w http.ResponseWriter, r *http.Request, id string) (store.Account, cfClient, bool) {
	if !a.admin(w, r) {
		return store.Account{}, cfClient{}, false
	}
	account, err := a.Store.Account(r.Context(), id)
	if err != nil {
		a.internal(w, r, err)
		return account, cfClient{}, false
	}
	if account.Provider != "cloudflare" {
		a.fail(w, r, 400, "invalid_provider", "此账户不是Cloudflare")
		return account, cfClient{}, false
	}
	httpClient, err := a.Store.HTTPClient(r.Context(), account.Config, 25*time.Second)
	if err != nil {
		a.providerError(w, r, err)
		return account, cfClient{}, false
	}
	client := cfClient{client: httpClient, config: account.Config, accountID: account.Config["account_id"]}
	return account, client, true
}
func (a *API) cfDomain(w http.ResponseWriter, r *http.Request) (store.Domain, cfClient, bool) {
	if !a.admin(w, r) {
		return store.Domain{}, cfClient{}, false
	}
	d, err := a.Store.Domain(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		a.internal(w, r, err)
		return d, cfClient{}, false
	}
	_, c, ok := a.cfAccount(w, r, d.AccountID)
	return d, c, ok
}
func (a *API) cfHostnames(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.cfDomain(w, r)
	if !ok {
		return
	}
	path := "/zones/" + url.PathEscape(d.ProviderDomainID) + "/custom_hostnames"
	switch r.Method {
	case "GET":
		q := url.Values{}
		if search := r.URL.Query().Get("search"); search != "" {
			q.Set("hostname", search)
		}
		rows, err := c.list(r, path, q)
		if err != nil {
			a.providerError(w, r, err)
			return
		}
		send(w, 200, map[string]any{"items": rows, "pagination": map[string]int{"total": len(rows)}})
	case "POST":
		var req struct {
			Hostname string            `json:"hostname"`
			SSL      map[string]any    `json:"ssl"`
			Origin   string            `json:"custom_origin_server,omitempty"`
			Metadata map[string]string `json:"custom_metadata,omitempty"`
		}
		if !a.decode(w, r, &req) {
			return
		}
		var err error
		req.Hostname, err = cfNormalizeHostname(req.Hostname, false)
		if err != nil {
			a.fail(w, r, 400, "invalid_hostname", err.Error())
			return
		}
		if req.SSL == nil {
			req.SSL = map[string]any{"method": "txt", "type": "dv", "settings": map[string]any{"min_tls_version": "1.2"}}
		}
		if err = cfValidateSSL(req.SSL); err != nil {
			a.fail(w, r, 400, "invalid_ssl", err.Error())
			return
		}
		if req.Origin != "" {
			req.Origin, err = cfNormalizeHostname(req.Origin, false)
			if err != nil {
				a.fail(w, r, 400, "invalid_origin", err.Error())
				return
			}
		}
		if req.Hostname == "" {
			a.fail(w, r, 400, "hostname_required", "需要主机名")
			return
		}
		result, err := c.call(r, "POST", path, req)
		if err != nil {
			a.providerError(w, r, err)
			return
		}
		if err = a.cfAudit(r, "hostname.create", req.Hostname, d.ID, nil); err != nil {
			a.internal(w, r, err)
			return
		}
		send(w, 201, result)
	}
}
func (a *API) cfHostname(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.cfDomain(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "hostname")
	path := "/zones/" + url.PathEscape(d.ProviderDomainID) + "/custom_hostnames/" + url.PathEscape(id)
	var body any
	if r.Method == http.MethodPatch {
		var req map[string]any
		if !a.decode(w, r, &req) {
			return
		}
		for _, key := range []string{"hostname", "custom_origin_server"} {
			if value, exists := req[key]; exists && value != nil {
				if value == "" && key == "custom_origin_server" {
					req[key] = nil
					continue
				}
				name, err := cfNormalizeHostname(cfString(value), false)
				if err != nil {
					a.fail(w, r, 400, "invalid_hostname", err.Error())
					return
				}
				req[key] = name
			}
		}
		if ssl, exists := req["ssl"]; exists {
			update := cfObject(ssl)
			if update == nil {
				a.fail(w, r, 400, "invalid_ssl", "SSL配置格式不正确")
				return
			}
			if err := cfValidateSSL(update); err != nil {
				a.fail(w, r, 400, "invalid_ssl", err.Error())
				return
			}
			raw, err := c.call(r, http.MethodGet, path, nil)
			if err != nil {
				a.providerError(w, r, err)
				return
			}
			current, err := cfParseMap(raw)
			if err != nil {
				a.providerError(w, r, err)
				return
			}
			req["ssl"] = cfMergeSSL(cfObject(current["ssl"]), update)
		}
		body = req
	}
	result, err := c.call(r, r.Method, path, body)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	if r.Method != http.MethodGet {
		if err = a.cfAudit(r, "hostname."+strings.ToLower(r.Method), id, d.ID, nil); err != nil {
			a.internal(w, r, err)
			return
		}
	}
	send(w, 200, result)
}
func (a *API) cfRefreshHostname(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.cfDomain(w, r)
	if !ok {
		return
	}
	path := "/zones/" + url.PathEscape(d.ProviderDomainID) + "/custom_hostnames/" + url.PathEscape(chi.URLParam(r, "hostname"))
	current, err := c.call(r, "GET", path, nil)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	var hostname struct {
		SSL struct {
			Method   string         `json:"method"`
			Type     string         `json:"type"`
			Settings map[string]any `json:"settings"`
		} `json:"ssl"`
	}
	if json.Unmarshal(current, &hostname) != nil {
		a.fail(w, r, 502, "provider_error", "无法读取当前验证设置")
		return
	}
	result, err := c.call(r, "PATCH", path, map[string]any{"ssl": hostname.SSL})
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	if err = a.cfAudit(r, "hostname.refresh", chi.URLParam(r, "hostname"), d.ID, nil); err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, result)
}
func (a *API) cfFallback(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.cfDomain(w, r)
	if !ok {
		return
	}
	var body any
	if r.Method == "PUT" {
		var req struct {
			Origin string `json:"origin"`
		}
		if !a.decode(w, r, &req) {
			return
		}
		if req.Origin == "" {
			a.fail(w, r, 400, "origin_required", "需要回退源站")
			return
		}
		var err error
		req.Origin, err = cfNormalizeHostname(req.Origin, false)
		if err != nil {
			a.fail(w, r, 400, "invalid_origin", err.Error())
			return
		}
		body = req
	}
	result, err := c.call(r, r.Method, "/zones/"+url.PathEscape(d.ProviderDomainID)+"/custom_hostnames/fallback_origin", body)
	var remoteErr *cfError
	if errors.As(err, &remoteErr) && remoteErr.Status == 404 && (r.Method == http.MethodGet || r.Method == http.MethodDelete) {
		send(w, 200, map[string]string{"origin": ""})
		return
	}
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	if r.Method != http.MethodGet {
		if err = a.cfAudit(r, "fallback."+strings.ToLower(r.Method), d.ID, d.ID, nil); err != nil {
			a.internal(w, r, err)
			return
		}
	}
	send(w, 200, result)
}
func (a *API) cfDCV(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.cfDomain(w, r)
	if !ok {
		return
	}
	result, err := c.call(r, "GET", "/zones/"+url.PathEscape(d.ProviderDomainID)+"/dcv_delegation/uuid", nil)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	send(w, 200, result)
}
func (a *API) cfTXTTargets(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.cfDomain(w, r); !ok {
		return
	}
	domains, err := a.Store.Domains(r.Context(), principal(r))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	hostname := r.URL.Query().Get("hostname")
	items := cfMatchingDomains(domains, hostname, "")
	send(w, 200, map[string]any{"items": items})
}
func (a *API) cfTunnelContext(w http.ResponseWriter, r *http.Request) (cfClient, bool) {
	_, c, ok := a.cfAccount(w, r, chi.URLParam(r, "id"))
	if !ok {
		return c, false
	}
	if c.config["api_token"] == "" && c.config["token"] == "" && !(c.config["auth"] == "1" && c.config["apikey"] != "") {
		a.fail(w, r, 422, "token_required", "Tunnel管理需要API Token")
		return c, false
	}
	if c.accountID == "" {
		accounts, err := c.list(r, "/accounts", nil)
		if err != nil {
			a.providerError(w, r, err)
			return c, false
		}
		if len(accounts) != 1 || cfString(accounts[0]["id"]) == "" {
			a.fail(w, r, 422, "account_id_required", "请明确配置Cloudflare Account ID")
			return c, false
		}
		c.accountID = cfString(accounts[0]["id"])
	}
	return c, true
}
func (a *API) cfTunnels(w http.ResponseWriter, r *http.Request) {
	c, ok := a.cfTunnelContext(w, r)
	if !ok {
		return
	}
	path := "/accounts/" + url.PathEscape(c.accountID) + "/cfd_tunnel"
	var body any
	if r.Method == "POST" {
		var req struct {
			Secret    string `json:"tunnel_secret"`
			Name      string `json:"name"`
			ConfigSrc string `json:"config_src"`
		}
		if !a.decode(w, r, &req) {
			return
		}
		if req.Name == "" {
			a.fail(w, r, 400, "name_required", "需要Tunnel名称")
			return
		}
		if req.ConfigSrc == "" {
			req.ConfigSrc = "cloudflare"
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			a.internal(w, r, err)
			return
		}
		req.Secret = base64.StdEncoding.EncodeToString(secret)
		body = req
	} else {
		rows, err := c.list(r, path, url.Values{"is_deleted": {"false"}})
		if err != nil {
			a.providerError(w, r, err)
			return
		}
		send(w, 200, map[string]any{"items": rows})
		return
	}
	result, err := c.call(r, r.Method, path, body)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	if err = a.cfAudit(r, "tunnel.create", "", "", nil); err != nil {
		a.internal(w, r, err)
		return
	}
	if r.Method == "GET" {
		send(w, 200, map[string]any{"items": result})
	} else {
		send(w, 201, result)
	}
}
func (a *API) cfTunnel(w http.ResponseWriter, r *http.Request) {
	c, ok := a.cfTunnelContext(w, r)
	if !ok {
		return
	}
	tunnel := chi.URLParam(r, "tunnel")
	var result json.RawMessage
	var err error
	if r.Method == http.MethodDelete {
		result, err = cfDeleteTunnel(r, c, tunnel)
	} else {
		result, err = c.call(r, r.Method, cfTunnelPath(c, tunnel), nil)
	}
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	if r.Method == http.MethodDelete {
		key := "cf-tunnel:" + chi.URLParam(r, "id") + ":" + tunnel
		var journal cfTunnelJournal
		if err = a.Store.Setting(r.Context(), key, &journal); err != nil && !errors.Is(err, sql.ErrNoRows) {
			a.internal(w, r, err)
			return
		}
		for _, receipt := range append(journal.Receipts, journal.Pending...) {
			if err = cfCleanupOwnedDNS(r, c, receipt, tunnel); err != nil {
				a.providerError(w, r, fmt.Errorf("Tunnel已删除，DNS清理需重试: %w", err))
				return
			}
		}
		if err = a.Store.SaveSetting(r.Context(), key, cfTunnelJournal{Stage: "complete"}); err != nil {
			a.internal(w, r, err)
			return
		}
		if err = a.cfAudit(r, "tunnel.delete", tunnel, "", nil); err != nil {
			a.internal(w, r, err)
			return
		}
	}
	send(w, 200, result)
}
func (a *API) cfTunnelToken(w http.ResponseWriter, r *http.Request) {
	c, ok := a.cfTunnelContext(w, r)
	if !ok {
		return
	}
	result, err := c.call(r, "GET", "/accounts/"+url.PathEscape(c.accountID)+"/cfd_tunnel/"+url.PathEscape(chi.URLParam(r, "tunnel"))+"/token", nil)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	if err = a.cfAudit(r, "tunnel.token", chi.URLParam(r, "tunnel"), "", nil); err != nil {
		a.internal(w, r, err)
		return
	}
	var token string
	if json.Unmarshal(result, &token) != nil {
		var value map[string]any
		if json.Unmarshal(result, &value) == nil {
			token = cfString(value["token"])
		}
	}
	if token == "" {
		a.fail(w, r, 502, "invalid_token", "Cloudflare未返回Tunnel Token")
		return
	}
	send(w, 200, map[string]string{"token": token})
}
func (a *API) cfIngress(w http.ResponseWriter, r *http.Request) {
	c, ok := a.cfTunnelContext(w, r)
	if !ok {
		return
	}
	tunnel := chi.URLParam(r, "tunnel")
	path := cfTunnelPath(c, tunnel) + "/configurations"
	if r.Method == http.MethodGet {
		raw, err := c.call(r, http.MethodGet, path, nil)
		if err != nil {
			a.providerError(w, r, err)
			return
		}
		config, err := cfConfig(raw)
		if err != nil {
			a.providerError(w, r, err)
			return
		}
		send(w, 200, map[string]any{"config": config, "version": cfHash(config)})
		return
	}
	var req struct {
		Config  map[string]any `json:"config"`
		Version string         `json:"version"`
		SyncDNS *bool          `json:"sync_dns"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if err := cfValidateIngress(req.Config); err != nil {
		a.fail(w, r, 400, "invalid_ingress", err.Error())
		return
	}
	domains, err := a.Store.Domains(r.Context(), principal(r))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	journalKey := "cf-tunnel:" + chi.URLParam(r, "id") + ":" + tunnel
	var journal cfTunnelJournal
	if err = a.Store.Setting(r.Context(), journalKey, &journal); err != nil && !errors.Is(err, sql.ErrNoRows) {
		a.internal(w, r, err)
		return
	}
	save := func(next cfTunnelJournal) error { return a.Store.SaveSetting(r.Context(), journalKey, next) }
	sync := req.SyncDNS == nil || *req.SyncDNS
	result, err := cfApplyIngress(r, c, tunnel, req.Config, req.Version, sync, domains, chi.URLParam(r, "id"), journal, save)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	if err = a.cfAudit(r, "tunnel.ingress", tunnel, "", map[string]any{"rule_count": len(cfArray(req.Config["ingress"]))}); err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, result)
}
func (a *API) cfTunnelRoutes(w http.ResponseWriter, r *http.Request) {
	c, ok := a.cfTunnelContext(w, r)
	if !ok {
		return
	}
	kind := chi.URLParam(r, "routekind")
	path := "/accounts/" + url.PathEscape(c.accountID) + "/teamnet/routes"
	if kind == "hostname-routes" {
		path = "/accounts/" + url.PathEscape(c.accountID) + "/zerotrust/routes/hostname"
	}
	tunnel := chi.URLParam(r, "tunnel")
	route := chi.URLParam(r, "route")
	var body any
	if r.Method == "GET" && route == "" {
		rows, err := c.list(r, path, url.Values{"is_deleted": {"false"}, "tunnel_id": {tunnel}})
		if err != nil {
			a.providerError(w, r, err)
			return
		}
		filtered := []map[string]any{}
		for _, row := range rows {
			if cfString(row["tunnel_id"]) == tunnel {
				filtered = append(filtered, row)
			}
		}
		send(w, 200, map[string]any{"items": filtered})
		return
	}
	if route != "" {
		path += "/" + url.PathEscape(route)
		raw, err := c.call(r, http.MethodGet, path, nil)
		if err != nil {
			a.providerError(w, r, err)
			return
		}
		var item map[string]any
		if json.Unmarshal(raw, &item) != nil || cfString(item["tunnel_id"]) != tunnel {
			a.fail(w, r, 404, "route_not_found", "路由不属于此Tunnel")
			return
		}
		if r.Method == http.MethodGet {
			send(w, 200, item)
			return
		}
	}
	if r.Method == "POST" {
		var req struct {
			Network        string `json:"network"`
			Hostname       string `json:"hostname"`
			VirtualNetwork string `json:"virtual_network_id,omitempty"`
			Comment        string `json:"comment"`
		}
		if !a.decode(w, r, &req) {
			return
		}
		if kind == "cidr-routes" {
			if _, _, err := net.ParseCIDR(req.Network); err != nil {
				a.fail(w, r, 400, "invalid_network", "CIDR网络格式不正确")
				return
			}
			payload := map[string]any{"network": req.Network, "tunnel_id": tunnel, "comment": req.Comment}
			if req.VirtualNetwork != "" {
				payload["virtual_network_id"] = req.VirtualNetwork
			}
			body = payload
		} else {
			var err error
			req.Hostname, err = cfNormalizeHostname(req.Hostname, false)
			if err != nil {
				a.fail(w, r, 400, "invalid_hostname", err.Error())
				return
			}
			if req.Hostname == "" {
				a.fail(w, r, 400, "hostname_required", "需要主机名")
				return
			}
			body = map[string]any{"hostname": req.Hostname, "tunnel_id": tunnel, "comment": req.Comment}
		}
	}
	result, err := c.call(r, r.Method, path, body)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	if r.Method != http.MethodGet {
		if err = a.cfAudit(r, "tunnel.route."+strings.ToLower(r.Method), tunnel, "", map[string]string{"kind": kind, "route": route}); err != nil {
			a.internal(w, r, err)
			return
		}
	}
	if r.Method == "GET" {
		send(w, 200, map[string]any{"items": result})
	} else {
		send(w, 200, result)
	}
}
