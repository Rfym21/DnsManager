package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/database"
	"github.com/dns-manager/dnsmgr/server/internal/notifications"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/go-chi/chi/v5"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func qqPrivateKey(secret string) ed25519.PrivateKey {
	if secret == "" {
		return nil
	}
	seed := []byte(secret)
	for len(seed) < ed25519.SeedSize {
		seed = append(seed, []byte(secret)...)
	}
	return ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
}
func verifyQQ(secret, timestamp, signature string, body []byte, now time.Time) bool {
	if secret == "" {
		return false
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || now.Sub(time.Unix(seconds, 0)) > 5*time.Minute || time.Unix(seconds, 0).Sub(now) > time.Minute {
		return false
	}
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	message := append([]byte(timestamp), body...)
	return ed25519.Verify(qqPrivateKey(secret).Public().(ed25519.PublicKey), message, sig)
}
func (a *API) qqWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var o store.Object
	var err error
	if id != "" {
		o, err = a.Store.Object(r.Context(), id)
	} else {
		objects, e := a.Store.Objects(r.Context(), "notification_channels")
		err = e
		for _, candidate := range objects {
			var channel notifications.Channel
			if json.Unmarshal(candidate.Data, &channel) == nil && channel.Provider == "qq" && candidate.Active {
				if o.ID != "" {
					a.fail(w, r, 409, "ambiguous_channel", "请使用通知渠道专属回调 URL")
					return
				}
				o = candidate
			}
		}
	}
	if err != nil || o.ID == "" || o.Kind != "notification_channels" || !o.Active {
		a.fail(w, r, 404, "not_found", "通知渠道不存在")
		return
	}
	var channel notifications.Channel
	if json.Unmarshal(o.Data, &channel) != nil || channel.Provider != "qq" || channel.Config["app_secret"] == "" || channel.Config["app_id"] == "" {
		a.fail(w, r, 400, "not_configured", "QQ 渠道配置不完整")
		return
	}
	if appID := r.Header.Get("X-Bot-Appid"); appID != "" && appID != channel.Config["app_id"] {
		a.fail(w, r, 403, "appid_mismatch", "应用 ID 不匹配")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		a.fail(w, r, 400, "invalid_payload", "回调内容不正确")
		return
	}
	var payload struct {
		Op   int    `json:"op"`
		Type string `json:"t"`
		ID   string `json:"id"`
		Data struct {
			Timestamp string `json:"event_ts"`
			Token     string `json:"plain_token"`
			ID        string `json:"id"`
			Author    struct {
				OpenID string `json:"user_openid"`
			} `json:"author"`
		} `json:"d"`
	}
	if json.Unmarshal(body, &payload) != nil {
		a.fail(w, r, 400, "invalid_payload", "回调内容不正确")
		return
	}
	if payload.Op == 13 {
		if payload.Data.Timestamp == "" || payload.Data.Token == "" || len(payload.Data.Token) > 1024 {
			a.fail(w, r, 400, "invalid_challenge", "验证参数不正确")
			return
		}
		signature := ed25519.Sign(qqPrivateKey(channel.Config["app_secret"]), []byte(payload.Data.Timestamp+payload.Data.Token))
		send(w, 200, map[string]string{"plain_token": payload.Data.Token, "signature": hex.EncodeToString(signature)})
		return
	}
	if !verifyQQ(channel.Config["app_secret"], r.Header.Get("X-Signature-Timestamp"), r.Header.Get("X-Signature-Ed25519"), body, time.Now()) {
		a.fail(w, r, 401, "invalid_signature", "回调签名无效或过期")
		return
	}
	if strings.EqualFold(payload.Type, "C2C_MESSAGE_CREATE") && payload.Data.Author.OpenID != "" && payload.Data.ID != "" {
		release, err := a.Store.LockResources(r.Context(), []string{"object:" + o.ID})
		if err != nil {
			a.internal(w, r, err)
			return
		}
		defer release()
		eventID := payload.ID
		if eventID == "" {
			eventID = payload.Data.ID
		}
		bound, err := a.bindQQChannel(r.Context(), o.ID, channel.Config, eventID, payload.Data.ID, payload.Data.Author.OpenID, true)
		if err != nil {
			a.internal(w, r, err)
			return
		}
		if bound {
			sum := sha256.Sum256([]byte(payload.Data.Author.OpenID))
			a.Store.Audit(r.Context(), "qqbot", "notification.qq.bind", "notification_channels", o.ID, "", "", map[string]string{"recipient_hash": hex.EncodeToString(sum[:])})
		}
	}
	send(w, 200, map[string]bool{"ok": true})
}

// Channel updates, signed-event deduplication, binding-window consumption and
// the directed reply are one commit. Delivery uses the ordinary outbox sender.
func (a *API) bindQQChannel(ctx context.Context, channelID string, expected map[string]string, eventID, messageID, openid string, requireWindow bool) (bool, error) {
	tx, err := a.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	bound, err := a.bindQQChannelTx(ctx, tx, channelID, expected, eventID, messageID, openid, requireWindow)
	if err != nil {
		return false, err
	}
	return bound, tx.Commit()
}
func (a *API) bindQQChannelTx(ctx context.Context, tx *database.Tx, channelID string, expected map[string]string, eventID, messageID, openid string, requireWindow bool) (bool, error) {
	var encrypted string
	var active bool
	err := tx.QueryRowContext(ctx, "SELECT data_ciphertext,active FROM objects WHERE id=? AND kind='notification_channels' FOR UPDATE", channelID).Scan(&encrypted, &active)
	if err != nil {
		return false, err
	}
	var data map[string]any
	if err = a.Store.Decrypt("object:"+channelID, encrypted, &data); err != nil {
		return false, err
	}
	cfg := cfObject(data["config"])
	if !active || data["provider"] != "qq" || cfg == nil || cfString(cfg["app_id"]) != expected["app_id"] || cfString(cfg["app_secret"]) != expected["app_secret"] {
		return false, nil
	}
	if requireWindow {
		err = tx.QueryRowContext(ctx, "SELECT ciphertext FROM settings WHERE name=? FOR UPDATE", "qq_binding:"+channelID).Scan(&encrypted)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		var binding struct {
			Until time.Time `json:"until"`
		}
		if err = a.Store.Decrypt("setting:qq_binding:"+channelID, encrypted, &binding); err != nil {
			return false, err
		}
		if binding.Until.IsZero() || !time.Now().Before(binding.Until) {
			return false, nil
		}
	}
	if eventID == "" || messageID == "" || openid == "" {
		return false, nil
	}
	dedup := "qqcallback:" + cryptobox.Hash(channelID+"\x00"+eventID)
	encrypted, err = a.Store.Encrypt("setting:"+dedup, map[string]any{"received_at": time.Now().UTC()})
	if err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, "INSERT IGNORE INTO settings(name,ciphertext,updated_at) VALUES(?,?,UTC_TIMESTAMP(6))", dedup, encrypted)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	changed := cfString(cfg["openid"]) != openid
	cfg["openid"] = openid
	encrypted, err = a.Store.Encrypt("object:"+channelID, data)
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE objects SET data_ciphertext=?,version=version+1,config_version=config_version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=?", encrypted, channelID); err != nil {
		return false, err
	}
	if requireWindow {
		if _, err = tx.ExecContext(ctx, "DELETE FROM settings WHERE name=?", "qq_binding:"+channelID); err != nil {
			return false, err
		}
	}
	if changed || requireWindow {
		message := notifications.Message{Title: "绑定成功", Body: "您已成功绑定QQ机器人消息通知，聚合DNS管理系统通知将通过本机器人发送。", Event: "notification.qq.bound", ResourceID: channelID, Data: map[string]any{"msg_id": messageID, "msg_seq": 1, "recipient_openid": openid}}
		if err = a.Store.EnqueueNotificationTx(ctx, tx, "qqbind:"+cryptobox.Hash(channelID+"\x00"+eventID), channelID, message); err != nil {
			return false, err
		}
	}
	return true, nil
}
