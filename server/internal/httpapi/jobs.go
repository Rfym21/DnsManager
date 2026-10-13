package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/automation"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/go-chi/chi/v5"
)

func (a *API) jobs(w http.ResponseWriter, r *http.Request) {
	if !principal(r).AllowsScope("dns:read") && !principal(r).AllowsScope("admin") {
		a.fail(w, r, 403, "forbidden", "API 凭据不能读取任务")
		return
	}
	items, err := a.Store.Jobs(r.Context(), principal(r), 100)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	visible := make([]store.Job, 0, len(items))
	for i := range items {
		if !a.canJob(r.Context(), principal(r), items[i]) {
			continue
		}
		items[i].Result = redactJSON(items[i].Result)
		visible = append(visible, items[i])
	}
	send(w, 200, map[string]any{"items": visible})
}
func (a *API) canJob(ctx context.Context, p store.Principal, j store.Job) bool {
	if !p.AllowsScope("dns:read") && !p.AllowsScope("admin") {
		return false
	}
	if !p.Admin() && j.OwnerID != p.User.ID {
		return false
	}
	if p.DomainID != "" && j.DomainID != p.DomainID {
		return false
	}
	ids := []string{}
	if j.DomainID != "" {
		ids = append(ids, j.DomainID)
	}
	if j.Kind == "record_batch" {
		var payload struct {
			DomainIDs []string `json:"domain_ids"`
		}
		if json.Unmarshal(j.Payload, &payload) != nil {
			return false
		}
		ids = append(ids, payload.DomainIDs...)
	} else if p.Token && !p.AllowsScope("admin") {
		return false
	}
	for _, id := range ids {
		allowed, err := a.Store.CanDomain(ctx, p, id, "dns:read")
		if err != nil || !allowed {
			return false
		}
	}
	return true
}
func (a *API) authorizedJob(w http.ResponseWriter, r *http.Request) (store.Job, bool) {
	j, err := a.Store.Job(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		a.internal(w, r, err)
		return j, false
	}
	p := principal(r)
	if !a.canJob(r.Context(), p, j) {
		a.fail(w, r, 403, "forbidden", "没有此任务的权限")
		return j, false
	}
	if j.DomainID != "" && !a.authorizeDomain(w, r, j.DomainID, "dns:read") {
		return j, false
	}
	if p.DomainID != "" && j.DomainID != p.DomainID {
		a.fail(w, r, 403, "forbidden", "没有此任务的权限")
		return j, false
	}
	return j, true
}
func (a *API) job(w http.ResponseWriter, r *http.Request) {
	j, ok := a.authorizedJob(w, r)
	if !ok {
		return
	}
	items, err := a.Store.JobItems(r.Context(), j.ID)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	j.Result = redactJSON(j.Result)
	for i := range items {
		items[i].Detail = redactJSON(items[i].Detail)
	}
	send(w, 200, map[string]any{"job": j, "items": items})
}
func (a *API) cancelJob(w http.ResponseWriter, r *http.Request) {
	j, ok := a.authorizedJob(w, r)
	if !ok {
		return
	}
	if p := principal(r); p.Token && !p.AllowsScope("dns:write") && !p.AllowsScope("admin") {
		a.fail(w, r, 403, "forbidden", "API 凭据不能取消任务")
		return
	}
	if err := a.Store.CancelJob(r.Context(), j.ID); err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}

func (a *API) jobLogs(w http.ResponseWriter, r *http.Request) {
	j, ok := a.authorizedJob(w, r)
	if !ok {
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	events, err := a.Store.JobEvents(r.Context(), j.ID, after)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	for i := range events {
		events[i].Data = redactJSON(events[i].Data)
	}
	send(w, 200, map[string]any{"items": events})
}
func (a *API) jobEvents(w http.ResponseWriter, r *http.Request) {
	j, ok := a.authorizedJob(w, r)
	if !ok {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		a.fail(w, r, 500, "stream_unavailable", "事件流不可用")
		return
	}
	controller := http.NewResponseController(w)
	controller.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	after, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)
	if after == 0 {
		after, _ = strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		// Revalidate current identity, grants, and the job on every poll, not just at connect.
		p := principal(r)
		if p.Token {
			var active int
			if a.Store.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.expires_at>UTC_TIMESTAMP(6) AND u.enabled=TRUE", p.TokenHash).Scan(&active) != nil || active == 0 {
				return
			}
		} else if p.SessionHash != "" {
			var active int
			if a.Store.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>UTC_TIMESTAMP(6) AND u.enabled=TRUE", p.SessionHash).Scan(&active) != nil || active == 0 {
				return
			}
		}
		user, e := a.Store.User(r.Context(), p.User.ID)
		if e != nil || !user.Enabled {
			return
		}
		p.User = user
		if !a.canJob(r.Context(), p, j) {
			return
		}
		if j.DomainID != "" {
			allowed, err := a.Store.CanDomain(r.Context(), p, j.DomainID, "dns:read")
			if err != nil || !allowed {
				return
			}
		}
		events, err := a.Store.JobEvents(r.Context(), j.ID, after)
		if err != nil {
			return
		}
		for _, event := range events {
			event.Data = redactJSON(event.Data)
			b, _ := json.Marshal(event)
			if _, err = fmt.Fprintf(w, "id: %s\nevent: log\ndata: %s\n\n", event.ID, b); err != nil {
				return
			}
			after, _ = strconv.ParseInt(event.ID, 10, 64)
		}
		current, err := a.Store.Job(r.Context(), j.ID)
		if err != nil {
			return
		}
		current.Result = redactJSON(current.Result)
		b, _ := json.Marshal(current)
		if _, err = fmt.Fprintf(w, "event: progress\ndata: %s\n\n", b); err != nil {
			return
		}
		flusher.Flush()
		if current.State != "queued" && current.State != "running" && current.State != "retry" {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-ticker.C:
		}
	}
}
func (a *API) recordBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DomainIDs []string     `json:"domain_ids"`
		Records   []dns.Record `json:"records"`
		Operation string       `json:"operation"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if len(req.DomainIDs) == 0 || len(req.Records) == 0 || len(req.DomainIDs)*len(req.Records) > 10000 {
		a.fail(w, r, 400, "invalid_batch", "批次应包含域名和记录，最多10000项")
		return
	}
	switch req.Operation {
	case "create", "update", "delete", "enable", "disable", "remark":
	default:
		a.fail(w, r, 400, "invalid_operation", "批量操作不正确")
		return
	}
	for _, id := range req.DomainIDs {
		if req.Operation != "create" && len(req.DomainIDs) != 1 {
			a.fail(w, r, 400, "invalid_batch", "记录 ID 属于单一域名，更新或删除时只能选择一个域名")
			return
		}
		for _, record := range req.Records {
			if req.Operation != "create" && record.ID == "" {
				a.fail(w, r, 400, "invalid_batch", "更新、删除与状态操作需要平台记录 ID")
				return
			}
		}
		if !a.authorizeDomain(w, r, id, "dns:write") {
			return
		}
	}
	if principal(r).DomainID != "" && len(req.DomainIDs) != 1 {
		a.fail(w, r, 403, "forbidden", "域名会话不能操作跨域名批次")
		return
	}
	b, _ := json.Marshal(req)
	key := r.Header.Get("Idempotency-Key")
	if len(key) > 128 {
		a.fail(w, r, 400, "invalid_key", "幂等键过长")
		return
	}
	if key != "" {
		key = principal(r).User.ID + ":" + key
	}
	domain := ""
	if len(req.DomainIDs) == 1 {
		domain = req.DomainIDs[0]
	}
	j, err := a.Store.CreateJob(r.Context(), store.Job{Kind: "record_batch", OwnerID: principal(r).User.ID, DomainID: domain, Payload: b, Total: len(req.DomainIDs) * len(req.Records), IdempotencyKey: key, Submission: store.Submission(principal(r))})
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 202, map[string]any{"job": j})
}
func (a *API) objectAction(w http.ResponseWriter, r *http.Request) {
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
	action := chi.URLParam(r, "action")
	if action == "bind" && o.Kind == "notification_channels" {
		var channel struct {
			Provider string `json:"provider"`
		}
		if json.Unmarshal(o.Data, &channel) != nil || channel.Provider != "qq" {
			a.fail(w, r, 400, "invalid_action", "此渠道不支持 QQ 绑定")
			return
		}
		until := time.Now().Add(10 * time.Minute)
		if err = a.Store.SaveSetting(r.Context(), "qq_binding:"+o.ID, map[string]any{"until": until}); err != nil {
			a.internal(w, r, err)
			return
		}
		send(w, 200, map[string]any{"url": a.Config.PublicURL + "/webhooks/qq/" + o.ID, "until": until})
		return
	}
	if action == "pause" || action == "resume" {
		o.Active = action == "resume"
		saved, err := a.Store.SaveObject(r.Context(), o, false)
		if err != nil {
			a.internal(w, r, err)
			return
		}
		saved.Data = redactJSON(saved.Data)
		send(w, 200, saved)
		return
	}
	allowed := map[string][]string{"certificates": {"execute", "renew", "revoke", "cancel"}, "deployments": {"execute", "test"}, "monitors": {"execute", "test"}, "schedules": {"execute", "preview"}, "optimizations": {"execute", "test", "quota"}, "issuer_accounts": {"test"}, "deploy_accounts": {"test"}, "notification_channels": {"test"}, "delegations": {"test"}, "proxy_profiles": {"test"}}
	valid := false
	for _, v := range allowed[o.Kind] {
		if v == action {
			valid = true
		}
	}
	if !valid {
		a.fail(w, r, 400, "invalid_action", "此资源不支持该操作")
		return
	}
	if action == "preview" {
		var d struct {
			Schedule automation.Schedule `json:"schedule"`
		}
		if json.Unmarshal(o.Data, &d) != nil {
			a.fail(w, r, 400, "invalid_schedule", "调度配置不正确")
			return
		}
		times, e := d.Schedule.Preview(time.Now(), 5)
		if e != nil {
			a.fail(w, r, 400, "invalid_schedule", e.Error())
			return
		}
		send(w, 200, map[string]any{"items": times})
		return
	}
	payload, _ := json.Marshal(map[string]any{"action": action, "config_version": o.ConfigVersion})
	maxAttempts := 3
	if o.Kind == "deployments" {
		var d automation.DeploymentData
		json.Unmarshal(o.Data, &d)
		policy, e := automation.NormalizeDeploymentRetryPolicy(d.RetryPolicy)
		if e != nil {
			a.fail(w, r, 400, "invalid_retry_policy", e.Error())
			return
		}
		maxAttempts = policy.MaxAttempts
	}
	key := r.Header.Get("Idempotency-Key")
	if key != "" {
		key = principal(r).User.ID + ":" + key
	}
	j, err := a.Store.CreateJob(r.Context(), store.Job{Kind: o.Kind, ResourceID: o.ID, DomainID: o.DomainID, OwnerID: principal(r).User.ID, Payload: payload, IdempotencyKey: key, MaxAttempts: maxAttempts, Submission: store.Submission(principal(r))})
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 202, map[string]any{"job": j})
}
func canonicalKind(kind string) string {
	switch kind {
	case "issuer-accounts":
		return "issuer_accounts"
	case "deployment-accounts", "deployment_accounts":
		return "deploy_accounts"
	case "notification-channels":
		return "notification_channels"
	case "domain-aliases":
		return "aliases"
	}
	return strings.ReplaceAll(kind, "-", "_")
}
