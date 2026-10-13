package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	sharedtransport "github.com/dns-manager/dnsmgr/server/internal/transport"
)

func (s Sender) configured(cfg map[string]string) (Sender, error) {
	if s.Now == nil {
		s.Now = time.Now
	}
	// An injected client already carries the store's selected proxy and fixture transport.
	if s.Client == nil {
		client, err := sharedtransport.Client(cfg["proxy_url"], 15*time.Second)
		if err != nil {
			return s, err
		}
		s.Client = client
	}
	return s, nil
}
func (s Sender) request(ctx context.Context, method, endpoint, contentType string, body io.Reader, headers map[string]string) ([]byte, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return nil, errors.New("通知URL无效")
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, errors.New("通知请求无效")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := s.Client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("通知连接失败")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil {
		return nil, errors.New("通知响应读取失败")
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("通知响应超过大小限制")
	}
	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("通知返回HTTP %d", res.StatusCode)
	}
	return raw, nil
}
func responseJSON(raw []byte) (map[string]any, error) {
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&result) != nil || result == nil {
		return nil, errors.New("通知渠道返回无效JSON")
	}
	return result, nil
}
func numeric(value any) (int64, bool) {
	switch v := value.(type) {
	case json.Number:
		n, e := v.Int64()
		return n, e == nil
	case string:
		n, e := strconv.ParseInt(v, 10, 64)
		return n, e == nil
	case float64:
		return int64(v), v == float64(int64(v))
	case int:
		return int64(v), true
	case int64:
		return v, true
	}
	return 0, false
}
func text(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}
func checkResponse(kind string, raw []byte) error {
	result, err := responseJSON(raw)
	if err != nil {
		if kind == "webhook" || kind == "custom_webhook" {
			return nil
		}
		return err
	}
	for _, key := range []string{"errcode", "code", "error_code", "StatusCode"} {
		if value, exists := result[key]; exists {
			code, valid := numeric(value)
			if !valid || code != 0 && code != 200 && !(kind == "wxpusher" && code == 1000) {
				return fmt.Errorf("通知渠道返回错误码 %s", text(value))
			}
		}
	}
	for _, key := range []string{"ok", "success", "result"} {
		if value, exists := result[key].(bool); exists && !value {
			return errors.New("通知渠道拒绝消息")
		}
	}
	switch kind {
	case "telegram":
		if result["ok"] != true {
			return errors.New("Telegram未确认发送成功")
		}
	case "wxpusher":
		if result["success"] != true {
			return errors.New("WxPusher未确认发送成功")
		}
	case "sendcloud":
		code, ok := numeric(result["statusCode"])
		if !ok || code != 200 {
			return errors.New("SendCloud未确认发送成功")
		}
	case "qq":
		if text(result["id"]) == "" {
			return errors.New("QQ机器人响应缺少消息ID")
		}
	case "dingtalk", "wecom":
		code, ok := numeric(result["errcode"])
		if !ok || code != 0 {
			return errors.New("机器人未确认发送成功")
		}
	case "feishu":
		_, a := result["code"]
		_, b := result["StatusCode"]
		if !a && !b {
			return errors.New("飞书未确认发送成功")
		}
	case "aliyun_mail":
		if text(result["Code"]) != "" || text(result["RequestId"]) == "" {
			return errors.New("阿里云邮件未确认发送成功")
		}
	}
	return nil
}
