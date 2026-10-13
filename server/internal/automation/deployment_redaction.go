package automation

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	deployprovider "github.com/dns-manager/dnsmgr/server/internal/providers/deploy"
	"github.com/dns-manager/dnsmgr/server/internal/redaction"
)

func redactDeploymentText(text string, config, target map[string]string, chain, private string) string {
	for _, values := range []map[string]string{config, target} {
		for key, value := range values {
			name := strings.ToLower(key)
			if redaction.Key(key) || name == "pass" || strings.HasSuffix(name, "_pass") {
				text = redactDeploymentMaterial(text, value)
			}
		}
	}
	for _, material := range []string{chain, private} {
		if material != "" {
			text = redactDeploymentMaterial(text, material)
			text = strings.ReplaceAll(text, base64.StdEncoding.EncodeToString([]byte(material)), "[redacted]")
		}
		for _, line := range strings.Split(material, "\n") {
			if len(line) > 16 {
				text = strings.ReplaceAll(text, line, "[redacted]")
			}
		}
	}
	return text
}

func redactDeploymentMaterial(text, material string) string {
	if material == "" {
		return text
	}
	text = strings.ReplaceAll(text, material, "[redacted]")
	// Provider errors sometimes contain an embedded JSON request body. Its
	// newlines and quotes are escaped even after the outer log is decoded.
	encoded, _ := json.Marshal(material)
	if len(encoded) > 2 {
		text = strings.ReplaceAll(text, string(encoded[1:len(encoded)-1]), "[redacted]")
	}
	return text
}

func redactDeploymentInfo(info deployprovider.Info, config, target map[string]string, chain, private string) deployprovider.Info {
	raw, _ := json.Marshal(info)
	var data map[string]any
	json.Unmarshal(raw, &data)
	var walk func(any) any
	walk = func(value any) any {
		switch item := value.(type) {
		case string:
			return redactDeploymentText(item, config, target, chain, private)
		case map[string]any:
			for key, value := range item {
				item[key] = walk(value)
			}
		case []any:
			for index, value := range item {
				item[index] = walk(value)
			}
		}
		return value
	}
	return deployprovider.Info(walk(data).(map[string]any))
}
