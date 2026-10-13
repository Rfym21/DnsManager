package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Channel struct {
	Provider string            `json:"provider"`
	Config   map[string]string `json:"config"`
	Events   []string          `json:"events"`
}
type Message struct {
	Title      string         `json:"title"`
	Body       string         `json:"body"`
	Event      string         `json:"event"`
	ResourceID string         `json:"resource_id,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
}
type Sender struct {
	Client *http.Client
	Now    func() time.Time
}

func (s Sender) Send(ctx context.Context, c Channel, m Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.Config = normalizeConfig(c.Config)
	var err error
	s, err = s.configured(c.Config)
	if err != nil {
		return err
	}
	cfg := c.Config
	m = renderMessage(m, cfg)
	switch c.Provider {
	case "smtp":
		return sendSMTP(ctx, cfg, m)
	case "sendcloud":
		return s.sendCloud(ctx, cfg, m)
	case "aliyun_mail", "aliyun":
		return s.sendAliyun(ctx, cfg, m)
	case "qq":
		if m.Event == "notification.qq.bound" {
			if recipient, ok := m.Data["recipient_openid"].(string); ok && recipient != "" {
				cfg["openid"] = recipient
			}
		}
		return s.sendQQ(ctx, cfg, m)
	case "wechat":
		return s.sendWechat(ctx, cfg, m)
	case "webhook", "custom_webhook":
		// Legacy webhook URLs identify the built-in Markdown/card wire protocol.
		u, _ := url.Parse(cfg["url"])
		host := ""
		if u != nil {
			host = strings.ToLower(u.Hostname())
		}
		if c.Provider == "webhook" {
			switch host {
			case "oapi.dingtalk.com":
				c.Provider = "dingtalk"
			case "qyapi.weixin.qq.com":
				c.Provider = "wecom"
			case "open.feishu.cn", "open.larksuite.com":
				c.Provider = "feishu"
			}
		}
		if c.Provider == "webhook" || c.Provider == "custom_webhook" {
			return s.sendWebhook(ctx, cfg, m)
		}
	}
	endpoint := cfg["url"]
	if cfg["endpoint"] != "" {
		endpoint = cfg["endpoint"]
	}
	var body map[string]any
	switch c.Provider {
	case "telegram":
		if err = require(cfg, "token", "chat_id"); err != nil {
			return err
		}
		base := strings.TrimRight(cfg["api_base"], "/")
		if base == "" {
			base = "https://api.telegram.org"
		}
		endpoint = base + "/bot" + cfg["token"] + "/sendMessage"
		body = map[string]any{"chat_id": cfg["chat_id"], "parse_mode": "HTML", "text": "<strong>" + html.EscapeString(m.Title) + "</strong>\n" + html.EscapeString(contentText(m.Body, false))}
		if topic := cfg["message_thread_id"]; topic != "" && topic != "0" {
			id, e := strconv.ParseInt(topic, 10, 64)
			if e != nil || id <= 0 {
				return errors.New("Telegram话题ID须为正整数")
			}
			body["message_thread_id"] = id
		}
	case "wxpusher":
		if err = require(cfg, "app_token", "uids"); err != nil && cfg["topic_ids"] == "" {
			return err
		}
		if cfg["app_token"] == "" {
			return errors.New("WxPusher app_token不能为空")
		}
		endpoint = "https://wxpusher.zjiecode.com/api/send/message"
		body = map[string]any{"appToken": cfg["app_token"], "summary": m.Title, "content": "# " + m.Title + "\n\n" + contentText(m.Body, true), "contentType": 3, "uids": splitValues(cfg["uids"])}
		if cfg["topic_ids"] != "" {
			ids := []int64{}
			for _, raw := range splitValues(cfg["topic_ids"]) {
				id, e := strconv.ParseInt(raw, 10, 64)
				if e != nil || id <= 0 {
					return errors.New("WxPusher topic_ids须为正整数")
				}
				ids = append(ids, id)
			}
			body["topicIds"] = ids
		}
	case "dingtalk":
		body = map[string]any{"msgtype": "markdown", "markdown": map[string]string{"title": m.Title, "text": "### " + m.Title + "\n\n" + contentText(m.Body, true)}}
		if users := cfg["at_users"]; users != "" {
			at := map[string]any{"isAtAll": users == "all"}
			if users != "all" {
				at["atMobiles"] = splitValues(users)
			}
			body["at"] = at
		}
		if secret := cfg["secret"]; secret != "" {
			u, e := url.Parse(endpoint)
			if e != nil {
				return errors.New("钉钉Webhook URL无效")
			}
			timestamp := strconv.FormatInt(s.Now().UnixMilli(), 10)
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(timestamp + "\n" + secret))
			q := u.Query()
			q.Set("timestamp", timestamp)
			q.Set("sign", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
			u.RawQuery = q.Encode()
			endpoint = u.String()
		}
	case "feishu":
		content := contentText(m.Body, true)
		if users := cfg["at_users"]; users != "" {
			for _, user := range splitValues(users) {
				if user == "all" {
					content += "\n<at id=all></at>"
				} else {
					content += "\n<at user_id=\"" + html.EscapeString(user) + "\"></at>"
				}
			}
		}
		color := "blue"
		if strings.Contains(m.Event, "failed") || strings.Contains(m.Event, "failure") || strings.Contains(m.Title, "失败") || strings.Contains(m.Title, "告警") {
			color = "red"
		} else if strings.Contains(m.Event, "recovery") {
			color = "green"
		} else if strings.Contains(m.Event, "expiring") {
			color = "yellow"
		}
		body = map[string]any{"msg_type": "interactive", "card": map[string]any{"schema": "2.0", "header": map[string]any{"template": color, "title": map[string]string{"tag": "plain_text", "content": m.Title}}, "body": map[string]any{"elements": []any{map[string]string{"tag": "markdown", "content": content}}}}}
		if secret := cfg["secret"]; secret != "" {
			timestamp := strconv.FormatInt(s.Now().Unix(), 10)
			mac := hmac.New(sha256.New, []byte(timestamp+"\n"+secret))
			body["timestamp"] = timestamp
			body["sign"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
		}
	case "wecom":
		content := "## " + m.Title + "\n" + contentText(m.Body, true)
		if users := cfg["at_users"]; users != "" {
			for _, user := range splitValues(users) {
				if user == "all" {
					user = "all"
				}
				content += "\n<@" + user + ">"
			}
		}
		body = map[string]any{"msgtype": "markdown", "markdown": map[string]string{"content": content}}
	default:
		return errors.New("未知通知渠道")
	}
	if cfg["endpoint"] != "" && c.Provider != "dingtalk" {
		endpoint = cfg["endpoint"]
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	result, err := s.request(ctx, http.MethodPost, endpoint, "application/json", bytes.NewReader(raw), nil)
	if err != nil {
		return err
	}
	return checkResponse(c.Provider, result)
}
func require(cfg map[string]string, fields ...string) error {
	for _, field := range fields {
		if strings.TrimSpace(cfg[field]) == "" {
			return fmt.Errorf("通知配置%s不能为空", field)
		}
	}
	return nil
}
func splitValues(raw string) []string {
	values := []string{}
	for _, v := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ';' }) {
		if v = strings.TrimSpace(v); v != "" {
			values = append(values, v)
		}
	}
	return values
}

func normalizeConfig(original map[string]string) map[string]string {
	cfg := map[string]string{}
	for key, value := range original {
		cfg[key] = value
	}
	aliases := map[string][]string{"uids": {"uid", "app_uid"}, "message_thread_id": {"topic_id", "thread_id"}, "at_users": {"at_user", "user"}, "app_token": {"appToken"}, "api_base": {"reverse_proxy_url"}, "AccessKeyId": {"access_key_id", "api_user"}, "AccessKeySecret": {"access_key_secret", "api_key"}}
	for key, names := range aliases {
		if cfg[key] != "" {
			continue
		}
		for _, name := range names {
			if cfg[name] != "" {
				cfg[key] = cfg[name]
				break
			}
		}
	}
	return cfg
}
