package notifications

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBuiltInNotificationsWireParity(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 34, 56, 0, time.UTC)
	for _, kind := range []string{"telegram", "wxpusher", "dingtalk", "feishu", "wecom", "sendcloud", "aliyun_mail", "qq", "wechat"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			var serverURL string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				raw, _ := io.ReadAll(r.Body)
				var body map[string]any
				json.Unmarshal(raw, &body)
				reply := map[string]any{"errcode": 0}
				switch kind {
				case "telegram":
					if body["parse_mode"] != "HTML" || body["message_thread_id"] != float64(42) || !strings.Contains(body["text"].(string), "&lt;unsafe&gt;") {
						t.Errorf("Telegram body=%s", raw)
					}
					reply = map[string]any{"ok": true}
				case "wxpusher":
					if body["contentType"] != float64(3) || len(body["uids"].([]any)) != 2 || len(body["topicIds"].([]any)) != 1 {
						t.Errorf("WxPusher body=%s", raw)
					}
					reply = map[string]any{"code": 1000, "success": true}
				case "dingtalk":
					timestamp := r.URL.Query().Get("timestamp")
					if timestamp != "1791894896000" {
						t.Errorf("Ding timestamp=%s", timestamp)
					}
					mac := hmac.New(sha256.New, []byte("fixture-sign-secret"))
					mac.Write([]byte(timestamp + "\nfixture-sign-secret"))
					if r.URL.Query().Get("sign") != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
						t.Error("Ding signature mismatch")
					}
					if body["msgtype"] != "markdown" || body["at"].(map[string]any)["isAtAll"] != true {
						t.Errorf("Ding body=%s", raw)
					}
				case "feishu":
					timestamp := body["timestamp"].(string)
					mac := hmac.New(sha256.New, []byte(timestamp+"\nfixture-sign-secret"))
					if body["sign"] != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
						t.Error("Feishu signature mismatch")
					}
					if body["msg_type"] != "interactive" {
						t.Errorf("Feishu body=%s", raw)
					}
					reply = map[string]any{"code": 0}
				case "wecom":
					if body["msgtype"] != "markdown" || !strings.Contains(body["markdown"].(map[string]any)["content"].(string), "<@all>") {
						t.Errorf("Wecom body=%s", raw)
					}
				case "sendcloud":
					values, _ := url.ParseQuery(string(raw))
					if values.Get("apiUser") != "fixture-api-user" || values.Get("fromName") != "DNS Manager" || !strings.Contains(values.Get("html"), "fixture body") {
						t.Errorf("SendCloud body=%s", raw)
					}
					reply = map[string]any{"statusCode": 200}
				case "aliyun_mail":
					values, _ := url.ParseQuery(string(raw))
					signature := values.Get("Signature")
					values.Del("Signature")
					keys := []string{}
					for key := range values {
						keys = append(keys, key)
					}
					sortStrings(keys)
					parts := []string{}
					for _, key := range keys {
						parts = append(parts, strings.ReplaceAll(url.QueryEscape(key), "+", "%20")+"="+strings.ReplaceAll(url.QueryEscape(values.Get(key)), "+", "%20"))
					}
					unsigned := strings.Join(parts, "&")
					mac := hmac.New(sha1.New, []byte("fixture-access-secret&"))
					mac.Write([]byte("POST&%2F&" + strings.ReplaceAll(url.QueryEscape(unsigned), "+", "%20")))
					if signature != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
						t.Error("Aliyun DirectMail wire signature mismatch")
					}
					if values.Get("Action") != "SingleSendMail" || values.Get("TextBody") != "fixture body" || values.Get("Version") != "2015-11-23" {
						t.Errorf("Aliyun parameters=%v", values)
					}
					reply = map[string]any{"RequestId": "fixture-request", "EnvId": "fixture-env"}
				case "qq":
					if r.URL.Path == "/app/getAppAccessToken" {
						if body["appId"] != "fixture-app" || body["clientSecret"] != "fixture-app-secret" {
							t.Error("QQ token credentials mismatch")
						}
						reply = map[string]any{"access_token": "fixture-qq-token"}
					} else {
						if r.URL.Path != "/v2/users/fixture-openid/messages" || r.Header.Get("Authorization") != "QQBot fixture-qq-token" || body["msg_type"] != float64(2) || body["msg_id"] != "reply-id" || body["msg_seq"] != float64(1) || !strings.Contains(body["markdown"].(map[string]any)["content"].(string), "**fixture body**") {
							t.Errorf("QQ request path=%s body=%s", r.URL.Path, raw)
						}
						reply = map[string]any{"id": "sent-id"}
					}
				case "wechat":
					if r.URL.Path == "/token" {
						reply = map[string]any{"access_token": "fixture-wx-token"}
					} else {
						if body["touser"] != "fixture-openid" || body["template_id"] != "fixture-template" || body["data"].(map[string]any)["keyword1"].(map[string]any)["value"] != "example.com" {
							t.Errorf("Wechat body=%s", raw)
						}
					}
				}
				json.NewEncoder(w).Encode(reply)
			}))
			defer server.Close()
			serverURL = server.URL
			cfg := map[string]string{"url": serverURL, "endpoint": serverURL, "token": "fixture-token", "chat_id": "123", "message_thread_id": "42", "app_token": "fixture-token", "uids": "user1,user2", "topic_ids": "9", "secret": "fixture-sign-secret", "at_users": "all", "api_user": "fixture-api-user", "api_key": "fixture-api-key", "from": "from@example.com", "to": "to@example.com", "from_name": "DNS Manager", "AccessKeyId": "fixture-access", "AccessKeySecret": "fixture-access-secret", "app_id": "fixture-app", "app_secret": "fixture-app-secret", "openid": "fixture-openid", "open_id": "fixture-openid", "template_id": "fixture-template", "api_base": serverURL, "template_data": `{"keyword1":{"value":"{{data.domain}}"}}`}
			message := Message{Title: "<unsafe>", Body: "<b>fixture body</b>", Event: "monitor.failure", Data: map[string]any{"msg_id": "reply-id", "domain": "example.com"}}
			if kind == "dingtalk" {
				delete(cfg, "endpoint")
			} // retain timestamp+sign query on real webhook endpoint
			if kind == "qq" {
				delete(cfg, "endpoint")
			}
			if kind == "wechat" {
				cfg["token_endpoint"] = serverURL + "/token"
			}
			err := (Sender{Now: func() time.Time { return now }}).Send(context.Background(), Channel{Provider: kind, Config: cfg}, message)
			expected := 1
			if kind == "qq" || kind == "wechat" {
				expected = 2
			}
			if err != nil || calls != expected {
				t.Fatalf("notification err=%v calls=%d", err, calls)
			}
		})
	}
}
func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

func TestWebhookMethodTemplatesHeadersAndFormat(t *testing.T) {
	for _, contentType := range []string{"application/json", "application/x-www-form-urlencoded", "text/plain"} {
		t.Run(contentType, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "PUT" || r.Header.Get("X-Fixture") != "yes" {
					t.Error("Webhook method/header lost")
				}
				raw, _ := io.ReadAll(r.Body)
				switch contentType {
				case "application/json":
					var object map[string]string
					if json.Unmarshal(raw, &object) != nil || object["text"] != "quoted\"title: line\nline" {
						t.Errorf("Webhook JSON=%s", raw)
					}
				case "application/x-www-form-urlencoded":
					values, _ := url.ParseQuery(string(raw))
					if values.Get("text") != "quoted\"title: line\nline" {
						t.Errorf("Webhook form=%s", raw)
					}
				case "text/plain":
					if string(raw) != "quoted\"title: line\nline" {
						t.Errorf("Webhook text=%s", raw)
					}
				}
				w.WriteHeader(204)
			}))
			defer server.Close()
			template := "{{title}}: {{content}}"
			if contentType == "application/json" {
				template = `{"text":"{title}: {content}"}`
			} else if contentType == "application/x-www-form-urlencoded" {
				template = "text={{title}}: {{content}}"
			}
			cfg := map[string]string{"url": server.URL, "method": "PUT", "content_type": contentType, "body_template": template, "content_format": "text", "headers": "X-Fixture: yes"}
			if err := (Sender{}).Send(context.Background(), Channel{Provider: "custom_webhook", Config: cfg}, Message{Title: `quoted"title`, Body: "line<br/>line"}); err != nil {
				t.Fatal(err)
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Query().Get("existing") != "keep" || r.URL.Query().Get("message") != "example.com / quoted\"title" {
			t.Errorf("GET Webhook query=%s", r.URL.RawQuery)
		}
		io.WriteString(w, "ok")
	}))
	defer server.Close()
	cfg := map[string]string{"url": server.URL + "?existing=keep", "method": "GET", "body_template": `{"message":"{{data.domain}} / {{title}}"}`}
	if err := (Sender{}).Send(context.Background(), Channel{Provider: "custom_webhook", Config: cfg}, Message{Title: `quoted"title`, Data: map[string]any{"domain": "example.com"}}); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationHTTPProxyAndReverseProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "private.example" || r.URL.Path != "/botfixture/sendMessage" {
			t.Errorf("proxy request URL=%s", r.URL)
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	defer proxy.Close()
	cfg := map[string]string{"token": "fixture", "chat_id": "123", "api_base": "http://private.example", "proxy_url": proxy.URL}
	if err := (Sender{}).Send(context.Background(), Channel{Provider: "telegram", Config: cfg}, Message{Body: "fixture"}); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationProviderFailuresAreNotDelivered(t *testing.T) {
	for _, fixture := range []struct{ kind, response string }{{"telegram", `{"ok":false}`}, {"wxpusher", `{"success":false,"code":1001}`}, {"sendcloud", `{"statusCode":500,"message":["failure"]}`}, {"qq", `{"code":0}`}, {"feishu", `{"StatusCode":999,"StatusMessage":"failed"}`}, {"aliyun_mail", `{"Code":"InvalidAccessKeyId"}`}, {"dingtalk", `{}`}} {
		if err := checkResponse(fixture.kind, []byte(fixture.response)); err == nil {
			t.Errorf("%s false success", fixture.kind)
		}
	}
}

func TestSMTPExplicitPlainAndMessageEncoding(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	var message string
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		io.WriteString(conn, "220 fixture ESMTP\r\n")
		for {
			line, e := reader.ReadString('\n')
			if e != nil {
				done <- e
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				io.WriteString(conn, "250-fixture\r\n250 SIZE 1000000\r\n")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				io.WriteString(conn, "250 accepted\r\n")
			case strings.HasPrefix(line, "DATA"):
				io.WriteString(conn, "354 send data\r\n")
				for {
					row, e := reader.ReadString('\n')
					if e != nil {
						done <- e
						return
					}
					if row == ".\r\n" {
						break
					}
					message += row
				}
				io.WriteString(conn, "250 delivered\r\n")
			case strings.HasPrefix(line, "QUIT"):
				io.WriteString(conn, "221 bye\r\n")
				done <- nil
				return
			default:
				done <- errors.New("unexpected SMTP command " + line)
				return
			}
		}
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	cfg := map[string]string{"host": host, "port": port, "tls_mode": "plain", "from": "sender@example.com", "from_name": "DNS Manager", "to": "one@example.com,two@example.com", "content_format": "html"}
	if err := (Sender{}).Send(context.Background(), Channel{Provider: "smtp", Config: cfg}, Message{Title: "中文 subject", Body: "<b>HTML fixture</b>"}); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, "Content-Type: text/html") || !strings.Contains(message, "From: \"DNS Manager\" <sender@example.com>") || !strings.Contains(message, "Subject: =?UTF-8?B?") {
		t.Errorf("SMTP message headers=%s", message)
	}
	parts := strings.SplitN(message, "\r\n\r\n", 2)
	body, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(parts[1]), "\r\n", ""))
	if err != nil || string(body) != "<b>HTML fixture</b>" {
		t.Fatalf("SMTP body=%s err=%v", body, err)
	}
}
