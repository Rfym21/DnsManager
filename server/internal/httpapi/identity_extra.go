package httpapi

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func (a *API) enrollTOTP(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Token || p.DomainID != "" {
		a.fail(w, r, 403, "forbidden", "此身份不能设置动态口令")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(p.User.PasswordHash), []byte(req.Password)) != nil {
		a.fail(w, r, 403, "password_invalid", "密码不正确")
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "DNS Manager", AccountName: p.User.Username})
	if err != nil {
		a.internal(w, r, err)
		return
	}
	if err = a.Store.SaveSetting(r.Context(), "totp_pending:"+p.User.ID, map[string]any{"secret": key.Secret(), "expires_at": time.Now().Add(10 * time.Minute)}); err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]string{"secret": key.Secret(), "otpauth_uri": key.URL()})
}
func (a *API) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Token || p.DomainID != "" {
		a.fail(w, r, 403, "forbidden", "此身份不能设置动态口令")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	var pending struct {
		Secret    string    `json:"secret"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := a.Store.Setting(r.Context(), "totp_pending:"+p.User.ID, &pending); err != nil {
		a.fail(w, r, 400, "totp_expired", "请重新开始动态口令设置")
		return
	}
	if time.Now().After(pending.ExpiresAt) || !totp.Validate(req.Code, pending.Secret) {
		a.fail(w, r, 400, "invalid_totp", "动态口令错误或已过期")
		return
	}
	enc, err := a.Store.Box.Seal("totp:"+p.User.ID, []byte(pending.Secret))
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
	if _, err = tx.ExecContext(r.Context(), "UPDATE users SET totp_secret=?,totp_enabled=TRUE,updated_at=UTC_TIMESTAMP(6) WHERE id=?", enc, p.User.ID); err == nil {
		_, err = tx.ExecContext(r.Context(), "DELETE FROM settings WHERE name=?", "totp_pending:"+p.User.ID)
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
func (a *API) disableTOTP(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Token || p.DomainID != "" {
		a.fail(w, r, 403, "forbidden", "此身份不能设置动态口令")
		return
	}
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(p.User.PasswordHash), []byte(req.Password)) != nil {
		a.fail(w, r, 403, "password_invalid", "密码不正确")
		return
	}
	if p.User.TOTPEnabled {
		secret, err := a.Store.Box.Open("totp:"+p.User.ID, p.User.TOTPSecret)
		if err != nil {
			a.internal(w, r, err)
			return
		}
		if !totp.Validate(req.Code, string(secret)) {
			a.fail(w, r, 403, "invalid_totp", "动态口令不正确")
			return
		}
	}
	_, err := a.Store.DB.ExecContext(r.Context(), "UPDATE users SET totp_secret=NULL,totp_enabled=FALSE,updated_at=UTC_TIMESTAMP(6) WHERE id=?", p.User.ID)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (a *API) loginLink(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !a.authorizeDomain(w, r, id, "dns:write") {
		return
	}
	d, err := a.Store.Domain(r.Context(), id)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	if !d.QuickloginEnabled {
		a.fail(w, r, 409, "quicklogin_disabled", "此域名未启用独立登录")
		return
	}
	token, err := cryptobox.RandomHex(32)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	_, err = a.Store.DB.ExecContext(r.Context(), "INSERT INTO login_tickets (token_hash,domain_id,issuer_id,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 5 MINUTE))", cryptobox.Hash(token), id, principal(r).User.ID)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 201, map[string]any{"token": token, "url": a.Config.PublicURL + "/domain-login#token=" + token, "expires_in": 300})
}
func (a *API) domainLogin(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		a.fail(w, r, 403, "forbidden", "来源不受信任")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if len(req.Token) != 64 {
		a.fail(w, r, 401, "invalid_ticket", "登录链接无效")
		return
	}
	tx, err := a.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer tx.Rollback()
	var domainID, userID string
	err = tx.QueryRowContext(r.Context(), "SELECT domain_id,issuer_id FROM login_tickets WHERE token_hash=? AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(6) FOR UPDATE", cryptobox.Hash(req.Token)).Scan(&domainID, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		a.fail(w, r, 401, "invalid_ticket", "登录链接无效或已使用")
		return
	}
	if err != nil {
		a.internal(w, r, err)
		return
	}
	u, err := a.Store.User(r.Context(), userID)
	if err != nil || !u.Enabled {
		a.fail(w, r, 401, "invalid_ticket", "授权账号已失效")
		return
	}
	allowed, err := a.Store.CanDomain(r.Context(), store.Principal{User: u}, domainID, "dns:write")
	if err != nil || !allowed {
		a.fail(w, r, 401, "invalid_ticket", "域名授权已失效")
		return
	}
	var enabled bool
	if err = tx.QueryRowContext(r.Context(), "SELECT quicklogin_enabled FROM domains WHERE id=?", domainID).Scan(&enabled); err != nil || !enabled {
		a.fail(w, r, 401, "invalid_ticket", "独立登录已关闭")
		return
	}
	if _, err = tx.ExecContext(r.Context(), "UPDATE login_tickets SET consumed_at=UTC_TIMESTAMP(6) WHERE token_hash=?", cryptobox.Hash(req.Token)); err != nil {
		a.internal(w, r, err)
		return
	}
	if err = tx.Commit(); err != nil {
		a.internal(w, r, err)
		return
	}
	token, csrf, err := a.Store.CreateSession(r.Context(), u, domainID, a.Config.SessionTTL)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "dnsmgr_session", Value: token, Path: "/", HttpOnly: true, Secure: a.Config.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: int(a.Config.SessionTTL.Seconds())})
	send(w, 200, map[string]any{"user": map[string]any{"id": u.ID, "username": domainID, "role": "domain", "enabled": true}, "domain_id": domainID, "csrf_token": csrf})
}
func (a *API) preferences(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.DomainID != "" || p.Token {
		a.fail(w, r, 403, "forbidden", "此身份不能修改个人偏好")
		return
	}
	var req struct {
		Theme        string `json:"theme"`
		Density      string `json:"density"`
		ReduceMotion bool   `json:"reduce_motion"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Theme != "light" && req.Theme != "dark" && req.Theme != "system" {
		a.fail(w, r, 400, "invalid_theme", "主题不正确")
		return
	}
	b, _ := json.Marshal(req)
	_, err := a.Store.DB.ExecContext(r.Context(), "UPDATE users SET preferences=?,updated_at=UTC_TIMESTAMP(6) WHERE id=?", b, p.User.ID)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, req)
}
func equalSecret(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
