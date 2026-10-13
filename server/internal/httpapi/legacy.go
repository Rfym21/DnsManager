package httpapi

import (
	"context"
	"crypto/md5"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/automation"
	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/go-chi/chi/v5"
)

type legacySourceKey struct{}

func (a *API) registerLegacy() {
	a.Router.Get("/quicklogin", a.legacyQuicklogin)
	a.Router.Get("/dmtask/status", a.legacyHealth)
	a.Router.Get("/optimizeip/status", a.legacyHealth)
	a.Router.Get("/cron", a.legacyCron)
	a.Router.Post("/qqbot/webhook", a.legacyQQWebhook)
	a.Router.Route("/api", func(r chi.Router) {
		r.Use(a.legacyAuthenticate)
		r.Post("/domain", a.legacyDomains)
		r.Post("/domain/{id}", a.legacyDomainInfo)
		r.Post("/record/{operation:data|add|update|delete|status|remark|batch}/{id}", a.legacyRecords)
		r.Post("/cert/order", a.legacyCertificate)
	})
}

func legacyReply(w http.ResponseWriter, status, code int, message string) {
	send(w, status, map[string]any{"code": code, "msg": message})
}

// The old digest is deliberately isolated here. It does not authenticate the
// request body and has no nonce; new clients should use scoped bearer tokens.
func (a *API) legacyAuthenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		if r.ParseForm() != nil {
			legacyReply(w, 403, -1, "认证参数不能为空")
			return
		}
		uid, err := strconv.ParseInt(r.PostForm.Get("uid"), 10, 64)
		timestamp, sign := r.PostForm.Get("timestamp"), r.PostForm.Get("sign")
		if err != nil || uid <= 0 || timestamp == "" || sign == "" {
			legacyReply(w, 403, -1, "认证参数不能为空")
			return
		}
		stamp, err := strconv.ParseInt(timestamp, 10, 64)
		now := time.Now().Unix()
		if err != nil || stamp < now-300 || stamp > now+300 {
			legacyReply(w, 403, -1, "时间戳不合法")
			return
		}
		var source string
		if err = a.Store.Setting(r.Context(), "migration.source_id", &source); err != nil || source == "" {
			legacyReply(w, 403, -1, "用户不存在")
			return
		}
		var userID string
		var enabled bool
		var ciphertext sql.NullString
		err = a.Store.DB.QueryRowContext(r.Context(), "SELECT user_id,api_enabled,api_key_ciphertext FROM legacy_identities WHERE source_id=? AND legacy_id=?", source, strconv.FormatInt(uid, 10)).Scan(&userID, &enabled, &ciphertext)
		if err != nil {
			legacyReply(w, 403, -1, "用户不存在")
			return
		}
		u, err := a.Store.User(r.Context(), userID)
		if err != nil {
			legacyReply(w, 403, -1, "用户不存在")
			return
		}
		if !u.Enabled {
			legacyReply(w, 403, -1, "该用户已被封禁")
			return
		}
		if !enabled {
			legacyReply(w, 403, -1, "该用户未开启API权限")
			return
		}
		key, err := a.Store.Box.Open("legacy-api:"+u.ID, ciphertext.String)
		if err != nil {
			legacyReply(w, 403, -1, "签名错误")
			return
		}
		digest := md5.Sum([]byte(strconv.FormatInt(uid, 10) + timestamp + string(key)))
		if subtle.ConstantTimeCompare([]byte(sign), []byte(hex.EncodeToString(digest[:]))) != 1 {
			legacyReply(w, 403, -1, "签名错误")
			return
		}
		ctx := context.WithValue(r.Context(), contextKey{}, store.Principal{User: u})
		ctx = context.WithValue(ctx, legacySourceKey{}, source)
		keys := []string{}
		if strings.HasPrefix(r.URL.Path, "/api/record/") && chi.URLParam(r, "operation") != "data" {
			id, e := a.legacyID(ctx, "domain", chi.URLParam(r, "id"))
			if e == nil {
				if d, e := a.Store.Domain(ctx, id); e == nil {
					keys = append(keys, "dns-account:"+d.AccountID)
				}
			}
		}
		release, e := a.Store.LockResources(ctx, keys)
		if e != nil {
			legacyReply(w, 409, -1, "该资源正在执行变更，请稍后重试")
			return
		}
		defer release()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *API) legacyID(ctx context.Context, table, id string) (string, error) {
	var target string
	// Old IDs are always source scoped. New opaque IDs are not accepted by this API.
	err := a.Store.DB.QueryRowContext(ctx, "SELECT target_id FROM legacy_resources WHERE source_id=? AND source_table=? AND source_id_value=?", ctx.Value(legacySourceKey{}), table, id).Scan(&target)
	return target, err
}

func (a *API) oldID(ctx context.Context, table, id string) string {
	var old string
	a.Store.DB.QueryRowContext(ctx, "SELECT source_id_value FROM legacy_resources WHERE source_id=? AND source_table=? AND target_id=?", ctx.Value(legacySourceKey{}), table, id).Scan(&old)
	return old
}

func (a *API) legacyDomain(ctx context.Context, d store.Domain) map[string]any {
	account, _ := a.Store.Account(ctx, d.AccountID)
	descriptor, _ := dns.Lookup(account.Provider)
	return map[string]any{"id": a.oldID(ctx, "domain", d.ID), "aid": a.oldID(ctx, "account", d.AccountID), "name": d.Name, "thirdid": d.ProviderDomainID, "type": account.Provider, "typename": descriptor.Name, "aremark": account.Remark, "remark": d.Remark, "category_name": d.Category, "is_hide": boolInt(d.Hidden), "is_sso": boolInt(d.QuickloginEnabled), "addtime": d.CreatedAt.Format("2006-01-02 15:04:05")}
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func formInt(v url.Values, key string, fallback int) int {
	if v.Get(key) == "" {
		return fallback
	}
	n, _ := strconv.Atoi(v.Get(key))
	return n
}

func (a *API) legacyDomains(w http.ResponseWriter, r *http.Request) {
	items, err := a.Store.Domains(r.Context(), principal(r))
	if err != nil {
		legacyReply(w, 200, -1, "读取域名失败")
		return
	}
	rows := []map[string]any{}
	v := r.PostForm
	for _, d := range items {
		row := a.legacyDomain(r.Context(), d)
		if row["id"] == "" {
			continue
		}
		if v.Get("id") != "" && row["id"] != v.Get("id") {
			continue
		}
		if v.Get("aid") != "" && row["aid"] != v.Get("aid") {
			continue
		}
		if v.Get("type") != "" && row["type"] != v.Get("type") {
			continue
		}
		if kw := strings.ToLower(v.Get("kw")); kw != "" && !strings.Contains(strings.ToLower(d.Name+" "+d.Remark), kw) {
			continue
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		key := v.Get("sort")
		if key == "" {
			key = "id"
		}
		left, right := fmt.Sprint(rows[i][key]), fmt.Sprint(rows[j][key])
		less := left < right
		if key == "id" {
			l, _ := strconv.Atoi(left)
			rr, _ := strconv.Atoi(right)
			less = l < rr
		}
		if v.Get("order") == "asc" {
			return less
		}
		return left != right && !less
	})
	total := len(rows)
	offset, limit := formInt(v, "offset", 0), formInt(v, "limit", 10)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	if limit < 0 {
		limit = 10
	}
	end := offset + limit
	if end > total {
		end = total
	}
	send(w, 200, map[string]any{"total": total, "rows": rows[offset:end]})
}

func (a *API) legacyProvider(w http.ResponseWriter, r *http.Request, write bool) (store.Domain, dns.Provider, bool) {
	id, err := a.legacyID(r.Context(), "domain", chi.URLParam(r, "id"))
	if err != nil {
		legacyReply(w, 200, -1, "域名不存在")
		return store.Domain{}, nil, false
	}
	action := "dns:read"
	if write {
		action = "dns:write"
	}
	allowed, err := a.Store.CanDomain(r.Context(), principal(r), id, action)
	if err != nil || !allowed {
		legacyReply(w, 200, -1, "无权限")
		return store.Domain{}, nil, false
	}
	d, err := a.Store.Domain(r.Context(), id)
	if err != nil {
		legacyReply(w, 200, -1, "域名不存在")
		return d, nil, false
	}
	account, err := a.Store.Account(r.Context(), d.AccountID)
	if err != nil {
		legacyReply(w, 200, -1, "DNS账户类型不存在或已失效")
		return d, nil, false
	}
	p, err := a.DNSFactory(account.Provider, account.Config, d.ProviderDomainID, d.ASCIIName)
	if err != nil {
		legacyReply(w, 200, -1, "DNS账户类型不存在或已失效")
		return d, nil, false
	}
	return d, p, true
}

func (a *API) legacyDomainInfo(w http.ResponseWriter, r *http.Request) {
	d, p, ok := a.legacyProvider(w, r, false)
	if !ok {
		return
	}
	lines, err := p.Lines(r.Context())
	if err != nil {
		legacyReply(w, 200, -1, safeProviderMessage(err))
		return
	}
	ttl, err := p.MinTTL(r.Context())
	if err != nil {
		legacyReply(w, 200, -1, safeProviderMessage(err))
		return
	}
	row := a.legacyDomain(r.Context(), d)
	desc := p.Descriptor()
	c := desc.Capabilities
	row["config"] = map[string]any{"type": desc.ID, "name": desc.Name, "status": c.Status, "remark": c.Remark, "page": c.ClientPagination, "sort": c.Sort, "weight": c.Weight, "add": c.CreateDomain, "redirect": c.Redirect, "log": c.Logs}
	row["recordLine"] = lines
	row["minTTL"] = max(ttl, 1)
	if r.PostForm.Get("loginurl") == "1" && d.QuickloginEnabled {
		url, err := a.makeLegacyLoginLink(r.Context(), d, principal(r).User.ID)
		if err != nil {
			legacyReply(w, 200, -1, "生成登录链接失败")
			return
		}
		row["loginurl"] = url
	}
	send(w, 200, map[string]any{"code": 0, "data": row})
}

func oldRecord(r dns.Record, lines map[string]string) map[string]any {
	var value any = r.Value
	if len(r.Values) > 1 {
		value = r.Values
	}
	name := lines[r.Line]
	if name == "" {
		name = r.Line
	}
	row := map[string]any{"RecordId": r.ID, "Name": r.Name, "Type": r.Type, "Value": value, "Line": r.Line, "LineName": name, "TTL": r.TTL, "MX": r.Priority, "Status": strconv.Itoa(boolInt(r.Enabled)), "Weight": r.Weight, "Remark": r.Remark, "UpdateTime": ""}
	if r.Proxied {
		row["Line"] = "1"
		row["LineName"] = "已代理"
	}
	var meta map[string]any
	json.Unmarshal(r.Metadata, &meta)
	for _, key := range []string{"modified_on", "updated_at", "UpdateTime"} {
		if meta[key] != nil {
			row["UpdateTime"] = meta[key]
			break
		}
	}
	return row
}

func (a *API) legacyRecords(w http.ResponseWriter, r *http.Request) {
	op := chi.URLParam(r, "operation")
	d, p, ok := a.legacyProvider(w, r, op != "data")
	if !ok {
		return
	}
	v := r.PostForm
	if op == "data" {
		limit, offset := formInt(v, "limit", 10), formInt(v, "offset", 0)
		page := 1
		if limit > 0 {
			page = offset/limit + 1
		}
		opts := dns.ListOptions{Page: page, PageSize: limit, Keyword: strings.TrimSpace(v.Get("keyword")), Name: strings.TrimSpace(v.Get("subdomain")), Value: strings.TrimSpace(v.Get("value")), Type: v.Get("type"), Line: v.Get("line"), Sort: v.Get("sortName"), Desc: strings.EqualFold(v.Get("sortOrder"), "desc")}
		if v.Get("status") != "" {
			b := v.Get("status") == "1"
			opts.Enabled = &b
		}
		data, err := p.ListRecords(r.Context(), opts)
		if err != nil {
			send(w, 200, map[string]any{"total": 0, "rows": []any{}})
			return
		}
		lines, _ := p.Lines(r.Context())
		names := map[string]string{}
		for _, l := range lines {
			names[l.ID] = l.Name
		}
		rows := make([]map[string]any, 0, len(data.Rows))
		for _, rr := range data.Rows {
			rows = append(rows, oldRecord(rr, names))
		}
		if p.Descriptor().Capabilities.ClientPagination {
			send(w, 200, rows)
		} else {
			send(w, 200, map[string]any{"total": data.Total, "rows": rows})
		}
		return
	}
	if op == "batch" {
		a.legacyBatch(w, r, d, p)
		return
	}
	id := strings.TrimSpace(v.Get("recordid"))
	var err error
	if op != "add" && id == "" {
		legacyReply(w, 200, -1, "参数不能为空")
		return
	}
	switch op {
	case "add", "update":
		record := dns.Record{ID: id, Name: strings.TrimSpace(v.Get("name")), Type: strings.TrimSpace(v.Get("type")), Value: strings.TrimSpace(v.Get("value")), Line: strings.TrimSpace(v.Get("line")), TTL: formInt(v, "ttl", 600), Remark: strings.TrimSpace(v.Get("remark")), Enabled: true, Proxied: p.Descriptor().ID == "cloudflare" && v.Get("line") == "1"}
		mx, weight := formInt(v, "mx", 1), formInt(v, "weight", 0)
		if record.Type == "MX" {
			record.Priority = &mx
		}
		if p.Descriptor().Capabilities.Weight {
			record.Weight = &weight
		}
		if record.Name == "" || record.Type == "" || record.Value == "" {
			legacyReply(w, 200, -1, "参数不能为空")
			return
		}
		if err = dns.ValidateRecord(record, d.ASCIIName); err == nil {
			if op == "add" {
				_, err = p.CreateRecord(r.Context(), record)
			} else {
				_, err = p.UpdateRecord(r.Context(), id, record)
			}
		}
	case "delete":
		err = p.DeleteRecord(r.Context(), id)
	case "status":
		err = p.SetStatus(r.Context(), id, v.Get("status") == "1")
	case "remark":
		err = p.SetRemark(r.Context(), id, strings.TrimSpace(v.Get("remark")))
	}
	labels := map[string]string{"add": "添加解析记录", "update": "修改解析记录", "delete": "删除解析记录", "status": "操作", "remark": "操作"}
	if err != nil {
		legacyReply(w, 200, -1, labels[op]+"失败，"+safeProviderMessage(err))
		return
	}
	if err = a.Store.Audit(r.Context(), principal(r).User.ID, "legacy.record."+op, "record", id, d.ID, "", map[string]any{"legacy": true}); err != nil {
		legacyReply(w, 200, -1, "平台已接受变更，审计保存失败，请刷新核对")
		return
	}
	legacyReply(w, 200, 0, labels[op]+"成功！")
}

func (a *API) legacyBatch(w http.ResponseWriter, r *http.Request, d store.Domain, p dns.Provider) {
	var records []struct {
		ID string `json:"RecordId"`
	}
	if json.Unmarshal([]byte(r.PostForm.Get("recordinfo")), &records) != nil || len(records) == 0 || len(records) > 1000 {
		legacyReply(w, 200, -1, "参数不能为空")
		return
	}
	action := r.PostForm.Get("action")
	if action == "group" {
		group, ok := p.(dns.GroupProvider)
		if !ok {
			legacyReply(w, 200, -1, "该DNS类型不支持分组")
			return
		}
		ids := []string{}
		for _, rr := range records {
			ids = append(ids, rr.ID)
		}
		if err := group.SetGroup(r.Context(), ids, r.PostForm.Get("groupid")); err != nil {
			legacyReply(w, 200, -1, "修改分组失败，"+safeProviderMessage(err))
			return
		}
		legacyReply(w, 200, 0, fmt.Sprintf("成功修改%d条记录的分组", len(ids)))
		return
	}
	success, failed := 0, 0
	for _, rr := range records {
		var err error
		switch action {
		case "open", "pause":
			err = p.SetStatus(r.Context(), rr.ID, action == "open")
		case "delete":
			err = p.DeleteRecord(r.Context(), rr.ID)
		case "remark":
			err = p.SetRemark(r.Context(), rr.ID, r.PostForm.Get("remark"))
		default:
			legacyReply(w, 200, -1, "参数不能为空")
			return
		}
		if err != nil {
			failed++
		} else {
			success++
		}
	}
	a.Store.Audit(r.Context(), principal(r).User.ID, "legacy.record.batch", "domain", d.ID, d.ID, "", map[string]any{"action": action, "success": success, "failed": failed})
	msg := fmt.Sprintf("成功%s%d条解析记录", map[string]string{"open": "启用", "pause": "暂停", "delete": "删除"}[action], success)
	if action == "remark" {
		msg = fmt.Sprintf("批量修改备注，成功%d条，失败%d条", success, failed)
	}
	legacyReply(w, 200, 0, msg)
}

func (a *API) legacyCertificate(w http.ResponseWriter, r *http.Request) {
	if !principal(r).Admin() {
		legacyReply(w, 200, -1, "无权限")
		return
	}
	id, err := a.legacyID(r.Context(), "cert_order", r.PostForm.Get("id"))
	if err != nil {
		legacyReply(w, 200, -1, "证书订单不存在")
		return
	}
	o, err := a.Store.Object(r.Context(), id)
	if err != nil || o.Kind != "certificates" {
		legacyReply(w, 200, -1, "证书订单不存在")
		return
	}
	var d automation.CertificateData
	if json.Unmarshal(o.Data, &d) != nil {
		legacyReply(w, 200, -1, "证书订单不可读取")
		return
	}
	pfx, err := certificatePFX(d.Fullchain, d.PrivateKey, "")
	if err != nil {
		legacyReply(w, 200, -1, "证书尚未签发")
		return
	}
	if err = a.Store.Audit(r.Context(), principal(r).User.ID, "legacy.certificate.download", "certificate", id, "", "", nil); err != nil {
		legacyReply(w, 200, -1, "证书审计保存失败")
		return
	}
	send(w, 200, map[string]any{"code": 0, "data": map[string]any{"id": r.PostForm.Get("id"), "crt": d.Fullchain, "key": d.PrivateKey, "pfx": base64.StdEncoding.EncodeToString(pfx), "issuetime": d.NotBefore.Format("2006-01-02 15:04:05"), "expiretime": d.NotAfter.Format("2006-01-02 15:04:05"), "domains": d.Domains}})
}

// Links keep the old URL shape while using a one-use persisted ticket. Existing
// Login links accept only one-time tickets issued by this application.
func (a *API) makeLegacyLoginLink(ctx context.Context, d store.Domain, userID string) (string, error) {
	var key string
	if err := a.Store.Setting(ctx, "legacy.sys_key", &key); err != nil || key == "" {
		return "", errors.New("legacy system key missing")
	}
	token, err := store.ID()
	if err != nil {
		return "", err
	}
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	if _, err = a.Store.DB.ExecContext(ctx, "INSERT INTO login_tickets(token_hash,domain_id,issuer_id,expires_at) VALUES(?,?,?,DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 1 HOUR))", cryptobox.Hash(token), d.ID, userID); err != nil {
		return "", err
	}
	digest := md5.Sum([]byte(key + d.Name + stamp + token + key))
	q := url.Values{"domain": {d.Name}, "timestamp": {stamp}, "token": {token}, "sign": {hex.EncodeToString(digest[:])}}
	return a.Config.PublicURL + "/quicklogin?" + q.Encode(), nil
}

func (a *API) legacyQuicklogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain, stamp, token, sign := q.Get("domain"), q.Get("timestamp"), q.Get("token"), q.Get("sign")
	n, err := strconv.ParseInt(stamp, 10, 64)
	now := time.Now().Unix()
	if err != nil || domain == "" || token == "" || sign == "" || n < now-3600 || n > now+300 {
		http.Error(w, "登录链接无效或已过期", 401)
		return
	}
	var key string
	if a.Store.Setting(r.Context(), "legacy.sys_key", &key) != nil || key == "" {
		http.Error(w, "登录链接无效", 401)
		return
	}
	digest := md5.Sum([]byte(key + domain + stamp + token + key))
	if subtle.ConstantTimeCompare([]byte(sign), []byte(hex.EncodeToString(digest[:]))) != 1 {
		http.Error(w, "登录链接签名错误", 401)
		return
	}
	tx, err := a.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "登录暂时不可用", 503)
		return
	}
	defer tx.Rollback()
	var domainID, userID string
	err = tx.QueryRowContext(r.Context(), "SELECT t.domain_id,t.issuer_id FROM login_tickets t JOIN domains d ON d.id=t.domain_id WHERE t.token_hash=? AND t.consumed_at IS NULL AND t.expires_at>UTC_TIMESTAMP(6) AND d.name=? AND d.quicklogin_enabled=TRUE FOR UPDATE", cryptobox.Hash(token), domain).Scan(&domainID, &userID)
	if err != nil {
		http.Error(w, "登录链接无效或已使用", 401)
		return
	}
	u, err := a.Store.User(r.Context(), userID)
	if err != nil || !u.Enabled {
		http.Error(w, "授权账号已失效", 401)
		return
	}
	allowed, err := a.Store.CanDomain(r.Context(), store.Principal{User: u}, domainID, "dns:write")
	if err != nil || !allowed {
		http.Error(w, "域名授权已失效", 401)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "UPDATE login_tickets SET consumed_at=UTC_TIMESTAMP(6) WHERE token_hash=?", cryptobox.Hash(token)); err != nil {
		http.Error(w, "登录暂时不可用", 503)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "登录暂时不可用", 503)
		return
	}
	session, _, err := a.Store.CreateSession(r.Context(), u, domainID, a.Config.SessionTTL)
	if err != nil {
		http.Error(w, "登录暂时不可用", 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "dnsmgr_session", Value: session, Path: "/", HttpOnly: true, Secure: a.Config.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: int(a.Config.SessionTTL.Seconds())})
	http.Redirect(w, r, "/domains/"+domainID, http.StatusSeeOther)
}
