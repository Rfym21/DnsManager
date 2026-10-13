package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

func (s Sender) sendCloud(ctx context.Context, cfg map[string]string, m Message) error {
	if err := require(cfg, "api_user", "api_key", "from", "to"); err != nil {
		return err
	}
	endpoint := "https://api.sendcloud.net/apiv2/mail/send"
	if cfg["endpoint"] != "" {
		endpoint = cfg["endpoint"]
	}
	content := m.Body
	if cfg["content_format"] != "html" {
		content = strings.ReplaceAll(html.EscapeString(contentText(content, false)), "\n", "<br/>")
	}
	values := url.Values{"apiUser": {cfg["api_user"]}, "apiKey": {cfg["api_key"]}, "from": {cfg["from"]}, "fromName": {cfg["from_name"]}, "to": {cfg["to"]}, "subject": {m.Title}, "html": {content}}
	raw, err := s.request(ctx, http.MethodPost, endpoint, "application/x-www-form-urlencoded", strings.NewReader(values.Encode()), nil)
	if err != nil {
		return err
	}
	return checkResponse("sendcloud", raw)
}
func escapeRPC(raw string) string { return strings.ReplaceAll(url.QueryEscape(raw), "+", "%20") }
func rpcQuery(params map[string]string) string {
	keys := []string{}
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := []string{}
	for _, key := range keys {
		parts = append(parts, escapeRPC(key)+"="+escapeRPC(params[key]))
	}
	return strings.Join(parts, "&")
}
func (s Sender) sendAliyun(ctx context.Context, cfg map[string]string, m Message) error {
	if err := require(cfg, "AccessKeyId", "AccessKeySecret", "from", "to"); err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	region := cfg["region"]
	if region == "" {
		region = "cn-hangzhou"
	}
	host := "dm.aliyuncs.com"
	version := "2015-11-23"
	if region != "cn-hangzhou" {
		host = "dm." + region + ".aliyuncs.com"
		version = "2017-06-22"
	}
	endpoint := "https://" + host + "/"
	if cfg["endpoint"] != "" {
		endpoint = cfg["endpoint"]
	}
	params := map[string]string{"Format": "JSON", "Version": version, "AccessKeyId": cfg["AccessKeyId"], "SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0", "SignatureNonce": hex.EncodeToString(nonce), "Timestamp": s.Now().UTC().Format("2006-01-02T15:04:05Z"), "Action": "SingleSendMail", "AccountName": cfg["from"], "ReplyToAddress": "false", "AddressType": "1", "ToAddress": cfg["to"], "FromAlias": cfg["from_name"], "Subject": m.Title}
	if cfg["content_format"] == "html" {
		params["HtmlBody"] = m.Body
	} else {
		params["TextBody"] = contentText(m.Body, false)
	}
	mac := hmac.New(sha1.New, []byte(cfg["AccessKeySecret"]+"&"))
	mac.Write([]byte("POST&%2F&" + escapeRPC(rpcQuery(params))))
	params["Signature"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	raw, err := s.request(ctx, http.MethodPost, endpoint, "application/x-www-form-urlencoded", strings.NewReader(rpcQuery(params)), nil)
	if err != nil {
		return err
	}
	return checkResponse("aliyun_mail", raw)
}
func (s Sender) sendWechat(ctx context.Context, cfg map[string]string, m Message) error {
	if err := require(cfg, "app_id", "app_secret", "open_id", "template_id"); err != nil {
		return err
	}
	tokenURL := "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=" + url.QueryEscape(cfg["app_id"]) + "&secret=" + url.QueryEscape(cfg["app_secret"])
	if cfg["token_endpoint"] != "" {
		tokenURL = cfg["token_endpoint"]
	}
	raw, err := s.request(ctx, http.MethodGet, tokenURL, "", nil, nil)
	if err != nil {
		return err
	}
	result, err := responseJSON(raw)
	if err != nil || text(result["access_token"]) == "" {
		return errors.New("微信token无效")
	}
	endpoint := "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=" + url.QueryEscape(text(result["access_token"]))
	if cfg["endpoint"] != "" {
		endpoint = cfg["endpoint"]
	}
	data := map[string]any{"first": map[string]string{"value": m.Title}, "remark": map[string]string{"value": contentText(m.Body, false)}}
	if template := cfg["template_data"]; template != "" {
		encoded := replaceTemplate(template, templateValues(m), func(v string) string { raw, _ := json.Marshal(v); return string(raw[1 : len(raw)-1]) })
		if json.Unmarshal([]byte(encoded), &data) != nil {
			return errors.New("微信公众号模板数据须为JSON对象")
		}
	}
	body := map[string]any{"touser": cfg["open_id"], "template_id": cfg["template_id"], "data": data}
	if cfg["link_url"] != "" {
		body["url"] = cfg["link_url"]
	}
	payload, _ := json.Marshal(body)
	raw, err = s.request(ctx, http.MethodPost, endpoint, "application/json", bytes.NewReader(payload), nil)
	if err != nil {
		return err
	}
	return checkResponse("wecom", raw)
}
func (s Sender) sendQQ(ctx context.Context, cfg map[string]string, m Message) error {
	if err := require(cfg, "app_id", "app_secret", "openid"); err != nil {
		return err
	}
	base := strings.TrimRight(cfg["api_base"], "/")
	if base == "" {
		base = "https://api.bot.qq.com"
	}
	tokenURL := base + "/app/getAppAccessToken"
	if cfg["token_endpoint"] != "" {
		tokenURL = cfg["token_endpoint"]
	}
	payload, _ := json.Marshal(map[string]string{"appId": cfg["app_id"], "clientSecret": cfg["app_secret"]})
	raw, err := s.request(ctx, http.MethodPost, tokenURL, "application/json", bytes.NewReader(payload), nil)
	if err != nil {
		return err
	}
	token, err := responseJSON(raw)
	if err != nil || text(token["access_token"]) == "" {
		return errors.New("QQ token无效")
	}
	body := map[string]any{"msg_type": 2, "markdown": map[string]string{"content": "# " + m.Title + "\n\n" + contentText(m.Body, true)}}
	msgID := cfg["msg_id"]
	if v := text(m.Data["msg_id"]); v != "" {
		msgID = v
	}
	if msgID != "" {
		body["msg_id"] = msgID
		body["msg_seq"] = 1
		if seq, ok := numeric(m.Data["msg_seq"]); ok && seq > 0 {
			body["msg_seq"] = seq
		}
	}
	if eventID := text(m.Data["event_id"]); eventID != "" {
		body["event_id"] = eventID
	}
	endpoint := base + "/v2/users/" + url.PathEscape(cfg["openid"]) + "/messages"
	if cfg["endpoint"] != "" {
		endpoint = cfg["endpoint"]
	}
	payload, _ = json.Marshal(body)
	raw, err = s.request(ctx, http.MethodPost, endpoint, "application/json", bytes.NewReader(payload), map[string]string{"Authorization": "QQBot " + text(token["access_token"])})
	if err != nil {
		return err
	}
	return checkResponse("qq", raw)
}
