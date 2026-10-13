package httpapi

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/automation"
	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/notifications"
)

func (a *API) legacyHealth(w http.ResponseWriter, r *http.Request) {
	query := "SELECT COUNT(*) FROM worker_heartbeats WHERE last_seen>DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 10 SECOND)"
	if strings.HasPrefix(r.URL.Path, "/optimizeip") {
		query = "SELECT COUNT(*) FROM objects WHERE kind='optimizations' AND active=TRUE AND updated_at>DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 HOUR)"
	}
	var count int
	err := a.Store.DB.QueryRowContext(r.Context(), query).Scan(&count)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err == nil && count > 0 {
		io.WriteString(w, "ok")
	} else {
		io.WriteString(w, "error")
	}
}

func (a *API) legacyCron(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if strings.Contains(r.UserAgent(), "Baiduspider") {
		return
	}
	var mode, key string
	if a.Store.Setting(r.Context(), "legacy.cron_type", &mode) != nil || mode != "1" || a.Store.Setting(r.Context(), "legacy.cron_key", &key) != nil || key == "" {
		io.WriteString(w, "未开启当前方式")
		return
	}
	if subtle.ConstantTimeCompare([]byte(key), []byte(r.URL.Query().Get("key"))) != 1 {
		io.WriteString(w, "访问密钥错误")
		return
	}
	if err := (&automation.Runner{Store: a.Store}).Tick(r.Context()); err != nil {
		http.Error(w, "任务调度失败，请查看服务日志", 503)
		return
	}
	io.WriteString(w, "success!")
}

func (a *API) legacyQQWebhook(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	var payload struct {
		Op   int    `json:"op"`
		Type string `json:"t"`
		ID   string `json:"id"`
		Data struct {
			EventTS string `json:"event_ts"`
			Token   string `json:"plain_token"`
			ID      string `json:"id"`
			Author  struct {
				OpenID string `json:"user_openid"`
			} `json:"author"`
		} `json:"d"`
	}
	if json.Unmarshal(body, &payload) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	var appID, secret string
	a.Store.Setting(r.Context(), "legacy.qqbot_appid", &appID)
	a.Store.Setting(r.Context(), "legacy.qqbot_appsecret", &secret)
	if appID == "" || secret == "" {
		http.Error(w, "not configured", 400)
		return
	}
	if header := r.Header.Get("X-Bot-Appid"); header != "" && header != appID {
		http.Error(w, "appid mismatch", 403)
		return
	}
	private := qqPrivateKey(secret)
	if payload.Op == 13 {
		if payload.Data.EventTS == "" || payload.Data.Token == "" || len(payload.Data.Token) > 1024 {
			http.Error(w, "bad request", 400)
			return
		}
		signature := ed25519.Sign(private, []byte(payload.Data.EventTS+payload.Data.Token))
		send(w, 200, map[string]string{"plain_token": payload.Data.Token, "signature": hex.EncodeToString(signature)})
		return
	}
	stamp := r.Header.Get("X-Signature-Timestamp")
	if !verifyQQ(secret, stamp, r.Header.Get("X-Signature-Ed25519"), body, time.Now()) {
		http.Error(w, "invalid signature", 401)
		return
	}
	// Persist callback deduplication and binding together. The signed body keeps
	// old timestamp semantics; duplicate deliveries cannot send a second reply.
	if strings.EqualFold(payload.Type, "C2C_MESSAGE_CREATE") && payload.Data.Author.OpenID != "" && payload.Data.ID != "" {
		eventID := payload.ID
		if eventID == "" {
			eventID = payload.Data.ID
		}
		tx, err := a.Store.DB.BeginTx(r.Context(), nil)
		if err != nil {
			http.Error(w, "error", 500)
			return
		}
		defer tx.Rollback()
		id := "qqcallback:" + cryptobox.Hash(eventID)
		enc, err := a.Store.Encrypt("setting:"+id, map[string]any{"received_at": time.Now().UTC()})
		if err != nil {
			http.Error(w, "error", 500)
			return
		}
		result, err := tx.ExecContext(r.Context(), "INSERT IGNORE INTO settings(name,ciphertext,updated_at) VALUES(?,?,UTC_TIMESTAMP(6))", id, enc)
		if err != nil {
			http.Error(w, "error", 500)
			return
		}
		n, _ := result.RowsAffected()
		if n > 0 {
			objects, readErr := a.Store.Objects(r.Context(), "notification_channels")
			if readErr != nil {
				http.Error(w, "error", 500)
				return
			}
			for _, object := range objects {
				var channel notifications.Channel
				if !object.Active || json.Unmarshal(object.Data, &channel) != nil || channel.Provider != "qq" || channel.Config["app_id"] != appID || channel.Config["app_secret"] != secret {
					continue
				}
				var migrated int
				if err = tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM legacy_resources WHERE target_id=? AND source_table='config' AND source_id_value='notification:qqbot'", object.ID).Scan(&migrated); err != nil {
					http.Error(w, "error", 500)
					return
				}
				if migrated == 0 {
					continue
				}
				if _, err = a.bindQQChannelTx(r.Context(), tx, object.ID, channel.Config, eventID, payload.Data.ID, payload.Data.Author.OpenID, false); err != nil {
					http.Error(w, "error", 500)
					return
				}
			}
			enc, err = a.Store.Encrypt("setting:legacy.qqbot_openid", payload.Data.Author.OpenID)
			if err != nil {
				http.Error(w, "error", 500)
				return
			}
			if _, err = tx.ExecContext(r.Context(), "INSERT INTO settings(name,ciphertext,updated_at) VALUES('legacy.qqbot_openid',?,UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE ciphertext=VALUES(ciphertext),version=version+1,updated_at=UTC_TIMESTAMP(6)", enc); err != nil {
				http.Error(w, "error", 500)
				return
			}
		}
		if err = tx.Commit(); err != nil {
			http.Error(w, "error", 500)
			return
		}
	}
	w.WriteHeader(200)
}
