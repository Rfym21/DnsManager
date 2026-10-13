package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func parseHeaders(raw string) (map[string]string, error) {
	headers := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return headers, nil
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		if json.Unmarshal([]byte(raw), &headers) != nil {
			return nil, errors.New("Webhook headers必须是字符串JSON对象")
		}
	} else {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok || strings.TrimSpace(key) == "" {
				return nil, errors.New("Webhook headers每行须为Name: value")
			}
			headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	for key, value := range headers {
		if strings.ContainsAny(key+value, "\r\n") || strings.ContainsAny(key, " \t:") {
			return nil, errors.New("Webhook header包含非法字符")
		}
	}
	return headers, nil
}
func (s Sender) sendWebhook(ctx context.Context, cfg map[string]string, m Message) error {
	endpoint := cfg["url"]
	if cfg["endpoint"] != "" {
		endpoint = cfg["endpoint"]
	}
	method := strings.ToUpper(cfg["method"])
	if method == "" {
		method = http.MethodPost
	}
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return errors.New("Webhook请求方法无效")
	}
	contentType := cfg["content_type"]
	if contentType == "" {
		contentType = "application/json"
	}
	baseType := strings.TrimSpace(strings.Split(contentType, ";")[0])
	switch cfg["content_format"] {
	case "text":
		m.Body = contentText(m.Body, false)
	case "markdown":
		m.Body = contentText(m.Body, true)
	case "", "html":
	default:
		return errors.New("Webhook内容格式无效")
	}
	headers, err := parseHeaders(cfg["headers"])
	if err != nil {
		return err
	}
	template := cfg["body_template"]
	if template == "" {
		if baseType == "application/x-www-form-urlencoded" {
			template = "title={{title}}&content={{content}}&event={{event}}"
		} else if baseType == "text/plain" {
			template = "{{title}}\n{{content}}"
		} else {
			template = `{"title":"{{title}}","content":"{{content}}","event":"{{event}}","resource_id":"{{resource_id}}"}`
		}
	}
	encode := func(v string) string { return v }
	if baseType == "application/json" {
		encode = func(v string) string { raw, _ := json.Marshal(v); return string(raw[1 : len(raw)-1]) }
	} else if baseType == "application/x-www-form-urlencoded" {
		encode = url.QueryEscape
	}
	body := replaceTemplate(template, templateValues(m), encode)
	if baseType == "application/json" && !json.Valid([]byte(body)) {
		return errors.New("自定义Webhook模板不是有效JSON")
	}
	if method == http.MethodGet {
		params := url.Values{}
		if baseType == "application/json" {
			var object map[string]any
			if json.Unmarshal([]byte(body), &object) != nil || object == nil {
				return errors.New("GET Webhook JSON模板须为对象")
			}
			for key, value := range object {
				switch v := value.(type) {
				case string:
					params.Set(key, v)
				default:
					raw, _ := json.Marshal(v)
					params.Set(key, string(raw))
				}
			}
		} else {
			params, err = url.ParseQuery(body)
			if err != nil {
				return errors.New("GET Webhook模板须为查询参数")
			}
		}
		u, e := url.Parse(endpoint)
		if e != nil {
			return errors.New("Webhook URL无效")
		}
		query := u.Query()
		for key, values := range params {
			query[key] = values
		}
		u.RawQuery = query.Encode()
		endpoint = u.String()
		body = ""
	}
	raw, err := s.request(ctx, method, endpoint, contentType, bytes.NewBufferString(body), headers)
	if err != nil {
		return err
	}
	return checkResponse("custom_webhook", raw)
}
