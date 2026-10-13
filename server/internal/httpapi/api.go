package httpapi

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/config"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type API struct {
	Store       *store.Store
	Config      config.Config
	Router      *chi.Mux
	DNSFactory  func(string, map[string]string, string, string) (dns.Provider, error)
	DoHClient   *http.Client
	DoHEndpoint string
}
type contextKey struct{}

func New(s *store.Store, c config.Config) *API {
	a := &API{Store: s, Config: c, Router: chi.NewRouter()}
	a.DNSFactory = func(kind string, cfg map[string]string, zoneID, zoneName string) (dns.Provider, error) {
		client, err := s.HTTPClient(context.Background(), cfg, 25*time.Second)
		if err != nil {
			return nil, err
		}
		return dns.NewWithOptions(kind, cfg, zoneID, zoneName, dns.FactoryOptions{Client: client})
	}
	a.Router.Use(middleware.RequestID, middleware.Recoverer, a.headers)
	a.Router.Get("/health/live", func(w http.ResponseWriter, r *http.Request) { send(w, 200, map[string]any{"status": "ok"}) })
	ready := func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.DB.PingContext(ctx); err != nil {
			a.fail(w, r, 503, "not_ready", "数据库暂时不可用")
			return
		}
		send(w, 200, map[string]any{"status": "ok"})
	}
	a.Router.Get("/health/ready", ready)
	a.Router.Head("/health/ready", ready)
	a.Router.Route("/api/v1", func(r chi.Router) {
		r.Get("/setup", a.setupStatus)
		r.Post("/setup", a.setup)
		r.Post("/auth/login", a.login)
		r.Get("/auth/captcha", a.captcha)
		r.Post("/auth/domain-login", a.domainLogin)
		r.Group(func(r chi.Router) {
			r.Use(a.authenticate, a.serializeMutation)
			r.Get("/auth/me", a.me)
			r.Post("/auth/logout", a.logout)
			r.Post("/auth/password", a.password)
			r.Post("/auth/totp/enroll", a.enrollTOTP)
			r.Post("/auth/totp/confirm", a.confirmTOTP)
			r.Post("/auth/totp/disable", a.disableTOTP)
			r.Put("/auth/preferences", a.preferences)
			r.Get("/dashboard", a.dashboard)
			r.Get("/domains", a.domains)
			r.Post("/domains", a.addDomain)
			r.Get("/domains/{id}", a.domain)
			r.Get("/domains/{id}/dates", a.domainDates)
			r.Put("/domains/{id}/dates", a.saveDomainDates)
			r.Post("/domains/{id}/dates/refresh", a.refreshDomainDates)
			r.Patch("/domains/{id}", a.updateDomain)
			r.Delete("/domains/{id}", a.deleteDomain)
			r.Post("/domains/{id}/login-links", a.loginLink)
			r.Get("/domains/{id}/cloudflare/hostnames", a.cfHostnames)
			r.Post("/domains/{id}/cloudflare/hostnames/batch", a.cfHostnamesBatch)
			r.Get("/domains/{id}/cloudflare/hostnames/{hostname}", a.cfHostname)
			r.Post("/domains/{id}/cloudflare/hostnames/{hostname}/txt", a.cfHostnameTXT)
			r.Post("/domains/{id}/cloudflare/hostnames", a.cfHostnames)
			r.Get("/domains/{id}/cloudflare/hostnames/txt-targets", a.cfTXTTargets)
			r.Patch("/domains/{id}/cloudflare/hostnames/{hostname}", a.cfHostname)
			r.Delete("/domains/{id}/cloudflare/hostnames/{hostname}", a.cfHostname)
			r.Post("/domains/{id}/cloudflare/hostnames/{hostname}/refresh", a.cfRefreshHostname)
			r.Get("/domains/{id}/cloudflare/fallback", a.cfFallback)
			r.Put("/domains/{id}/cloudflare/fallback", a.cfFallback)
			r.Delete("/domains/{id}/cloudflare/fallback", a.cfFallback)
			r.Get("/domains/{id}/cloudflare/dcv", a.cfDCV)
			r.Post("/domains/{id}/cloudflare/dcv", a.cfDCVDelegate)
			r.Get("/accounts", a.accounts)
			r.Get("/accounts/{id}", a.accountDetail)
			r.Post("/accounts", a.addAccount)
			r.Patch("/accounts/{id}", a.updateAccount)
			r.Delete("/accounts/{id}", a.deleteAccount)
			r.Post("/accounts/{id}/verify", a.verifyAccount)
			r.Get("/accounts/{id}/domains", a.providerDomains)
			r.Get("/accounts/{id}/cloudflare/tunnels", a.cfTunnels)
			r.Post("/accounts/{id}/cloudflare/tunnels", a.cfTunnels)
			r.Delete("/accounts/{id}/cloudflare/tunnels/{tunnel}", a.cfTunnel)
			r.Get("/accounts/{id}/cloudflare/tunnels/{tunnel}/token", a.cfTunnelToken)
			r.Get("/accounts/{id}/cloudflare/tunnels/{tunnel}/ingress", a.cfIngress)
			r.Put("/accounts/{id}/cloudflare/tunnels/{tunnel}/ingress", a.cfIngress)
			r.Get("/accounts/{id}/cloudflare/tunnels/{tunnel}/{routekind:cidr-routes|hostname-routes}", a.cfTunnelRoutes)
			r.Post("/accounts/{id}/cloudflare/tunnels/{tunnel}/{routekind:cidr-routes|hostname-routes}", a.cfTunnelRoutes)
			r.Delete("/accounts/{id}/cloudflare/tunnels/{tunnel}/{routekind:cidr-routes|hostname-routes}/{route}", a.cfTunnelRoutes)
			r.Get("/accounts/{id}/cloudflare/tunnels/{tunnel}/{routekind:cidr-routes|hostname-routes}/{route}", a.cfTunnelRoutes)
			r.Get("/providers", a.providers)
			r.Get("/domains/{id}/records", a.records)
			r.Get("/domains/{id}/records/{record}", a.recordDetail)
			r.Get("/domains/{id}/records/{record}/check", a.recordCheck)
			r.Post("/domains/{id}/records", a.createRecord)
			r.Patch("/domains/{id}/records/{record}", a.updateRecord)
			r.Delete("/domains/{id}/records/{record}", a.deleteRecord)
			r.Put("/domains/{id}/records/{record}/status", a.recordStatus)
			r.Put("/domains/{id}/records/{record}/remark", a.recordRemark)
			r.Get("/domains/{id}/capabilities", a.recordCapabilities)
			r.Get("/domains/{id}/record-groups", a.recordGroups)
			r.Put("/domains/{id}/record-groups", a.setRecordGroup)
			r.Get("/domains/{id}/record-logs", a.recordLogs)
			r.Get("/domains/{id}/weights", a.recordWeights)
			r.Put("/domains/{id}/weights", a.setRecordWeight)
			r.Get("/domains/{id}/provider-aliases", a.providerAliases)
			r.Post("/domains/{id}/provider-aliases", a.writeProviderAlias)
			r.Delete("/domains/{id}/provider-aliases/{alias}", a.writeProviderAlias)
			r.Post("/record-batches", a.recordBatch)
			r.Post("/record-imports/preview", a.recordImportPreview)
			r.Get("/jobs", a.jobs)
			r.Get("/jobs/{id}", a.job)
			r.Get("/jobs/{id}/events", a.jobEvents)
			r.Get("/jobs/{id}/logs", a.jobLogs)
			r.Post("/certificates/import", a.certificateImport)
			r.Post("/certificates/{id}/download", a.certificateDownload)
			r.Post("/jobs/{id}/cancel", a.cancelJob)
			r.Post("/jobs/{id}/retry", a.retryJob)
			r.Post("/jobs/{id}/reconcile", a.reconcileJob)
			r.Post("/jobs/{id}/resolve", a.resolveDeploymentJob)
			r.Get("/objects/{kind}", a.objects)
			r.Post("/objects/{kind}", a.createObject)
			r.Get("/objects/{kind}/{id}", a.object)
			r.Patch("/objects/{kind}/{id}", a.updateObject)
			r.Delete("/objects/{kind}/{id}", a.deleteObject)
			r.Post("/objects/{kind}/{id}/actions/{action}", a.objectAction)
			r.Get("/users", a.users)
			r.Post("/users", a.createUser)
			r.Patch("/users/{id}", a.updateUser)
			r.Delete("/users/{id}", a.deleteUser)
			r.Get("/users/{id}/grants", a.grants)
			r.Put("/users/{id}/grants", a.setGrants)
			r.Get("/audit", a.audit)
			r.Get("/settings", a.settings)
			r.Put("/settings", a.saveSettings)
			r.Get("/tokens", a.tokens)
			r.Post("/tokens", a.createToken)
			r.Delete("/tokens/{id}", a.deleteToken)
		})
	})
	a.registerLegacy()
	a.Router.Post("/webhooks/qq/{id}", a.qqWebhook)
	a.Router.NotFound(a.static)
	return a
}

func principal(r *http.Request) store.Principal {
	return r.Context().Value(contextKey{}).(store.Principal)
}
func send(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
func (a *API) fail(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	send(w, status, map[string]any{"code": code, "message": message, "request_id": middleware.GetReqID(r.Context())})
}
func (a *API) internal(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrResultUnknown) {
		a.fail(w, r, 409, "result_unknown", "此资源存在外部结果未知的任务，请先核对并恢复原任务")
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		a.fail(w, r, 404, "not_found", "资源不存在")
		return
	}
	if errors.Is(err, store.ErrConflict) {
		a.fail(w, r, 409, "conflict", "资源已存在或被修改，请刷新后重试")
		return
	}
	if errors.Is(err, store.ErrResourceBusy) {
		a.fail(w, r, 409, "resource_busy", "该资源正在执行变更，请稍后重试")
		return
	}
	if errors.Is(err, store.ErrForbidden) {
		a.fail(w, r, 403, "forbidden", "没有操作权限")
		return
	}
	slog.Error("request failed", "request_id", middleware.GetReqID(r.Context()), "path", r.URL.Path, "error_type", errorType(err))
	a.fail(w, r, 500, "internal_error", "操作未完成，请查看服务日志或重试")
}
func errorType(err error) string {
	if err == nil {
		return "none"
	}
	return "internal"
}
func (a *API) decode(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		a.fail(w, r, 400, "invalid_json", "请求格式或字段不正确")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		a.fail(w, r, 400, "invalid_json", "请求必须包含单个 JSON 对象")
		return false
	}
	return true
}
func (a *API) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
func (a *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p store.Principal
		var err error
		if bearer := r.Header.Get("Authorization"); strings.HasPrefix(bearer, "Bearer ") {
			p, err = a.Store.Token(r.Context(), strings.TrimPrefix(bearer, "Bearer "))
		} else {
			cookie, e := r.Cookie("dnsmgr_session")
			if e != nil {
				a.fail(w, r, 401, "unauthorized", "请先登录")
				return
			}
			p, err = a.Store.Session(r.Context(), cookie.Value)
		}
		if err != nil {
			a.fail(w, r, 401, "unauthorized", "登录已失效，请重新登录")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && !p.Token {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(p.CSRF)) != 1 || !a.sameOrigin(r) {
				a.fail(w, r, 403, "csrf_failed", "安全校验失败，请刷新后重试")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, p)))
	})
}
func (a *API) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	configured, err := url.Parse(a.Config.PublicURL)
	if err != nil {
		return false
	}
	return origin == configured.Scheme+"://"+configured.Host
}
func (a *API) admin(w http.ResponseWriter, r *http.Request) bool {
	p := principal(r)
	if !p.Admin() || !p.AllowsScope("admin") {
		a.fail(w, r, 403, "forbidden", "此操作需要管理员权限")
		return false
	}
	return true
}
func (a *API) authorizeDomain(w http.ResponseWriter, r *http.Request, id, action string) bool {
	ok, err := a.Store.CanDomain(r.Context(), principal(r), id, action)
	if err != nil {
		a.internal(w, r, err)
		return false
	}
	if !ok {
		a.fail(w, r, 403, "forbidden", "没有该域名的操作权限")
		return false
	}
	return true
}
