package httpapi

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func (a *API) setupStatus(w http.ResponseWriter, r *http.Request) {
	installed, err := a.Store.Installed(r.Context())
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]any{"installed": installed, "setup_token_required": a.Config.SetupToken != "", "login_captcha": a.loginCaptchaEnabled(r)})
}
func validPassword(value string) bool { return utf8.RuneCountInString(value) >= 12 && len(value) <= 72 }
func validUsername(value string) bool {
	return len(value) >= 2 && len(value) <= 128 && !strings.ContainsAny(value, "\n\r\t")
}
func (a *API) setup(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		a.fail(w, r, 403, "forbidden", "请求来源不受信任")
		return
	}
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		SetupToken string `json:"setup_token"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if a.Config.SetupToken != "" {
		if subtle.ConstantTimeCompare([]byte(req.SetupToken), []byte(a.Config.SetupToken)) != 1 {
			a.fail(w, r, 403, "setup_token_required", "安装令牌不正确")
			return
		}
	} else {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			a.fail(w, r, 403, "local_setup_only", "远程安装需要设置 SETUP_TOKEN_FILE")
			return
		}
	}
	req.Username = strings.TrimSpace(req.Username)
	if !validUsername(req.Username) || !validPassword(req.Password) {
		a.fail(w, r, 400, "validation_failed", "用户名至少 2 字符，密码需 12 字符以上且不超过 72 字节")
		return
	}
	u, err := a.Store.Install(r.Context(), req.Username, req.Password)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	a.Store.Audit(r.Context(), u.ID, "install", "user", u.ID, "", "", map[string]any{"username": u.Username})
	a.establishSession(w, r, u)
}
func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		a.fail(w, r, 403, "forbidden", "请求来源不受信任")
		return
	}
	var req struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		Code          string `json:"code"`
		CaptchaToken  string `json:"captcha_token"`
		CaptchaAnswer string `json:"captcha_answer"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	key := cryptobox.Hash(strings.ToLower(req.Username) + "|" + host)
	limited, err := a.Store.LoginLimited(r.Context(), key)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	if limited {
		a.fail(w, r, 429, "rate_limited", "登录失败次数过多，请 15 分钟后重试")
		return
	}
	if a.loginCaptchaEnabled(r) && !a.consumeCaptcha(r, req.CaptchaToken, req.CaptchaAnswer) {
		a.fail(w, r, 400, "captcha_invalid", "验证码不正确或已过期，请刷新后重试")
		return
	}
	u, err := a.Store.UserByName(r.Context(), req.Username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		a.internal(w, r, err)
		return
	}
	hash := u.PasswordHash
	if err != nil {
		hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	}
	passwordOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) == nil
	valid := err == nil && u.Enabled && passwordOK
	if !valid {
		a.Store.LoginFailure(r.Context(), key)
		a.fail(w, r, 401, "invalid_credentials", "用户名或密码不正确")
		return
	}
	if u.TOTPEnabled {
		if req.Code == "" {
			a.fail(w, r, 401, "totp_required", "请输入动态口令")
			return
		}
		secret, err := a.Store.Box.Open("totp:"+u.ID, u.TOTPSecret)
		if err != nil {
			a.internal(w, r, err)
			return
		}
		if !totp.Validate(req.Code, string(secret)) {
			a.Store.LoginFailure(r.Context(), key)
			a.fail(w, r, 401, "invalid_totp", "动态口令不正确")
			return
		}
	}
	a.Store.LoginSuccess(r.Context(), key)
	a.establishSession(w, r, u)
}
func (a *API) establishSession(w http.ResponseWriter, r *http.Request, u store.User) {
	token, csrf, err := a.Store.CreateSession(r.Context(), u, "", a.Config.SessionTTL)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if err = a.Store.Audit(r.Context(), u.ID, "auth.login", "user", u.ID, "", middleware.GetReqID(r.Context()), map[string]any{"outcome": "succeeded", "method": "password", "remote_ip": host, "totp": u.TOTPEnabled}); err != nil {
		a.Store.DB.ExecContext(r.Context(), "DELETE FROM sessions WHERE token_hash=?", cryptobox.Hash(token))
		a.internal(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "dnsmgr_session", Value: token, Path: "/", HttpOnly: true, Secure: a.Config.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: int(a.Config.SessionTTL.Seconds())})
	send(w, 200, map[string]any{"user": u, "csrf_token": csrf})
}
func (a *API) me(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	send(w, 200, map[string]any{"user": p.User, "csrf_token": p.CSRF, "domain_id": p.DomainID})
}
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	tx, err := a.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer tx.Rollback()
	if p.SessionHash != "" {
		if _, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE token_hash=?", p.SessionHash); err != nil {
			a.internal(w, r, err)
			return
		}
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor_id,action,resource_type,resource_id,request_id,detail,created_at) VALUES(?,'auth.logout','user',?,?,JSON_OBJECT(),UTC_TIMESTAMP(6))", p.User.ID, p.User.ID, middleware.GetReqID(r.Context())); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "dnsmgr_session", Value: "", Path: "/", HttpOnly: true, Secure: a.Config.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	send(w, 200, map[string]bool{"ok": true})
}
func (a *API) password(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.DomainID != "" || p.Token {
		a.fail(w, r, 403, "forbidden", "此会话不能修改密码")
		return
	}
	var req struct {
		Current  string `json:"current_password"`
		Password string `json:"password"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(p.User.PasswordHash), []byte(req.Current)) != nil || !validPassword(req.Password) {
		a.fail(w, r, 400, "validation_failed", "当前密码不正确，或新密码不符合要求")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	tx, err := a.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), "UPDATE users SET password_hash=?,updated_at=UTC_TIMESTAMP(6) WHERE id=?", string(hash), p.User.ID); err == nil {
		_, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE user_id=?", p.User.ID)
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
func (a *API) users(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	rows, err := a.Store.DB.QueryContext(r.Context(), "SELECT "+"id,username,password_hash,role,enabled,totp_secret,totp_enabled,preferences,created_at FROM users ORDER BY created_at")
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer rows.Close()
	list := []store.User{}
	for rows.Next() {
		var u store.User
		var secret sql.NullString
		var preferences []byte
		if err = rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Enabled, &secret, &u.TOTPEnabled, &preferences, &u.CreatedAt); err != nil {
			a.internal(w, r, err)
			return
		}
		u.Preferences = preferences
		list = append(list, u)
	}
	if err = rows.Err(); err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]any{"items": list})
}
func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if !validUsername(req.Username) || !validPassword(req.Password) || (req.Role != "admin" && req.Role != "restricted") {
		a.fail(w, r, 400, "validation_failed", "用户名、密码或角色不正确")
		return
	}
	id, err := store.ID()
	if err != nil {
		a.internal(w, r, err)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	_, err = a.Store.DB.ExecContext(r.Context(), "INSERT INTO users (id,username,password_hash,role,enabled,preferences,created_at,updated_at) VALUES (?,?,?,?,TRUE,'{}',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))", id, req.Username, string(hash), req.Role)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	u, err := a.Store.User(r.Context(), id)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 201, u)
}
func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Enabled  bool   `json:"enabled"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if !validUsername(req.Username) || (req.Role != "admin" && req.Role != "restricted") {
		a.fail(w, r, 400, "validation_failed", "用户名或角色不正确")
		return
	}
	if id == principal(r).User.ID && (!req.Enabled || req.Role != "admin") {
		a.fail(w, r, 400, "last_admin", "不能禁用或降级当前管理员")
		return
	}
	// Serialize changes so concurrent requests cannot remove the last administrator.
	tx, err := a.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(r.Context(), "SELECT id FROM users WHERE role='admin' AND enabled=TRUE FOR UPDATE")
	if err != nil {
		a.internal(w, r, err)
		return
	}
	admins := []string{}
	for rows.Next() {
		var value string
		rows.Scan(&value)
		admins = append(admins, value)
	}
	rows.Close()
	if len(admins) == 1 && admins[0] == id && (!req.Enabled || req.Role != "admin") {
		a.fail(w, r, 409, "last_admin", "必须保留一个有效管理员")
		return
	}
	_, err = tx.ExecContext(r.Context(), "UPDATE users SET username=?,role=?,enabled=?,updated_at=UTC_TIMESTAMP(6) WHERE id=?", req.Username, req.Role, req.Enabled, id)
	if err == nil {
		_, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE user_id=?", id)
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
func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	u, err := a.Store.User(r.Context(), id)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	if u.Role == "admin" {
		a.fail(w, r, 409, "admin_protected", "管理员账户需要先降级后再删除")
		return
	}
	_, err = a.Store.DB.ExecContext(r.Context(), "DELETE FROM users WHERE id=?", id)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}

type Grant struct {
	DomainID    string   `json:"domain_id"`
	Permissions []string `json:"permissions"`
}

func (a *API) grants(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	rows, err := a.Store.DB.QueryContext(r.Context(), "SELECT domain_id,permissions FROM domain_grants WHERE user_id=?", chi.URLParam(r, "id"))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer rows.Close()
	list := []Grant{}
	for rows.Next() {
		var g Grant
		var b []byte
		if err = rows.Scan(&g.DomainID, &b); err != nil {
			a.internal(w, r, err)
			return
		}
		if err = json.Unmarshal(b, &g.Permissions); err != nil {
			a.internal(w, r, err)
			return
		}
		list = append(list, g)
	}
	send(w, 200, map[string]any{"items": list})
}
func (a *API) setGrants(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var req struct {
		Items []Grant `json:"items"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	id := chi.URLParam(r, "id")
	if _, err := a.Store.User(r.Context(), id); err != nil {
		a.internal(w, r, err)
		return
	}
	for _, grant := range req.Items {
		if _, err := a.Store.Domain(r.Context(), grant.DomainID); err != nil {
			a.internal(w, r, err)
			return
		}
		for _, permission := range grant.Permissions {
			if permission != "dns:read" && permission != "dns:write" {
				a.fail(w, r, 400, "invalid_permission", "域名授权权限不正确")
				return
			}
		}
	}
	tx, err := a.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM domain_grants WHERE user_id=?", id); err != nil {
		a.internal(w, r, err)
		return
	}
	for _, grant := range req.Items {
		b, _ := json.Marshal(grant.Permissions)
		if _, err = tx.ExecContext(r.Context(), "INSERT INTO domain_grants (user_id,domain_id,permissions) VALUES (?,?,?)", id, grant.DomainID, b); err != nil {
			a.internal(w, r, err)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (a *API) tokens(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.DomainID != "" || p.Token {
		a.fail(w, r, 403, "forbidden", "此会话不能管理 API 凭据")
		return
	}
	rows, err := a.Store.DB.QueryContext(r.Context(), "SELECT id,name,scopes,created_at,expires_at FROM api_tokens WHERE user_id=? ORDER BY created_at DESC", p.User.ID)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name string
		var scopes json.RawMessage
		var created, expires time.Time
		if err = rows.Scan(&id, &name, &scopes, &created, &expires); err != nil {
			a.internal(w, r, err)
			return
		}
		items = append(items, map[string]any{"id": id, "name": name, "scopes": scopes, "created_at": created, "expires_at": expires})
	}
	send(w, 200, map[string]any{"items": items})
}
func (a *API) createToken(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.DomainID != "" || p.Token {
		a.fail(w, r, 403, "forbidden", "此会话不能创建 API 凭据")
		return
	}
	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
		Days   int      `json:"days"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Name == "" || req.Days < 1 || req.Days > 365 {
		a.fail(w, r, 400, "validation_failed", "需要凭据名称，期限为 1–365 天")
		return
	}
	for _, scope := range req.Scopes {
		if scope != "dns:read" && scope != "dns:write" && !(scope == "admin" && p.Admin()) {
			a.fail(w, r, 400, "invalid_scope", "API 权限范围不正确")
			return
		}
	}
	id, err := store.ID()
	if err != nil {
		a.internal(w, r, err)
		return
	}
	secret, err := cryptobox.RandomHex(32)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	token := "dm_" + secret
	scopes, _ := json.Marshal(req.Scopes)
	_, err = a.Store.DB.ExecContext(r.Context(), "INSERT INTO api_tokens (id,user_id,name,token_hash,scopes,created_at,expires_at) VALUES (?,?,?,?,?,UTC_TIMESTAMP(6),?)", id, p.User.ID, req.Name, cryptobox.Hash(token), scopes, time.Now().UTC().Add(time.Duration(req.Days)*24*time.Hour))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 201, map[string]any{"id": id, "token": token, "name": req.Name})
}
func (a *API) deleteToken(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.DomainID != "" || p.Token {
		a.fail(w, r, 403, "forbidden", "此会话不能管理 API 凭据")
		return
	}
	_, err := a.Store.DB.ExecContext(r.Context(), "DELETE FROM api_tokens WHERE id=? AND user_id=?", chi.URLParam(r, "id"), p.User.ID)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
