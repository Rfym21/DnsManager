// Package redaction keeps API responses and durable execution logs free of
// credentials, including credentials embedded in webhook/proxy URLs and headers.
package redaction

import (
	"encoding/json"
	"strings"
)

func Key(key string) bool {
	k := strings.ToLower(key)
	if k == "key_type" || k == "key_size" {
		return false
	}
	return strings.Contains(k, "secret") || strings.Contains(k, "password") ||
		strings.Contains(k, "private") || strings.Contains(k, "token") ||
		strings.Contains(k, "key") || strings.Contains(k, "authorization") ||
		k == "credential" || k == "credentials" || k == "headers" ||
		k == "cookie" || k == "url" || k == "endpoint" || k == "proxy_url"
}

// Value returns a copy. A sensitive aggregate is replaced as a whole so its
// blank representation can preserve the original value during configuration edits.
func Value(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			if Key(key) {
				out[key] = ""
			} else {
				out[key] = Value(item)
			}
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(v))
		for key, item := range v {
			if Key(key) {
				out[key] = ""
			} else {
				out[key] = item
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = Value(item)
		}
		return out
	default:
		return value
	}
}

func JSON(raw json.RawMessage) json.RawMessage {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return json.RawMessage(`{}`)
	}
	out, err := json.Marshal(Value(value))
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return out
}
