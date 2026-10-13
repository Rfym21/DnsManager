package notifications

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	nethtml "golang.org/x/net/html"
)

var placeholder = regexp.MustCompile(`\{\{([a-zA-Z0-9_.]+)\}\}|\{(title|content)\}`)

func templateValues(m Message) map[string]string {
	values := map[string]string{"title": m.Title, "content": m.Body, "event": m.Event, "resource_id": m.ResourceID}
	var walk func(string, any)
	walk = func(key string, v any) {
		if object, ok := v.(map[string]any); ok {
			for child, value := range object {
				walk(key+"."+child, value)
			}
			return
		}
		switch value := v.(type) {
		case string:
			values[key] = value
		case nil:
			values[key] = ""
		default:
			raw, err := json.Marshal(value)
			if err == nil {
				values[key] = string(raw)
			} else {
				values[key] = fmt.Sprint(value)
			}
		}
	}
	for key, value := range m.Data {
		walk("data."+key, value)
	}
	return values
}
func replaceTemplate(template string, values map[string]string, encode func(string) string) string {
	return placeholder.ReplaceAllStringFunc(template, func(token string) string {
		match := placeholder.FindStringSubmatch(token)
		key := match[1]
		if key == "" {
			key = match[2]
		}
		value, ok := values[key]
		if !ok {
			return ""
		}
		if encode != nil {
			return encode(value)
		}
		return value
	})
}
func renderMessage(m Message, cfg map[string]string) Message {
	values := templateValues(m)
	if template := cfg["title_template"]; template != "" {
		m.Title = replaceTemplate(template, values, nil)
	}
	if template := cfg["content_template"]; template != "" {
		m.Body = replaceTemplate(template, values, nil)
	}
	return m
}

// The tokenizer decodes HTML entities and drops markup while retaining line breaks.
func contentText(content string, markdown bool) string {
	tokenizer := nethtml.NewTokenizer(strings.NewReader(content))
	var result strings.Builder
	skip := 0
	for {
		kind := tokenizer.Next()
		switch kind {
		case nethtml.ErrorToken:
			if tokenizer.Err() == io.EOF {
				return strings.TrimSpace(result.String())
			}
			return strings.TrimSpace(result.String())
		case nethtml.TextToken:
			if skip == 0 {
				result.Write(tokenizer.Text())
			}
		case nethtml.StartTagToken, nethtml.SelfClosingTagToken:
			name, _ := tokenizer.TagName()
			tag := string(name)
			if tag == "script" || tag == "style" {
				skip++
				continue
			}
			if skip > 0 {
				continue
			}
			switch tag {
			case "br", "p", "div", "li":
				if result.Len() > 0 {
					result.WriteByte('\n')
				}
			case "b", "strong":
				if markdown {
					result.WriteString("**")
				}
			}
		case nethtml.EndTagToken:
			name, _ := tokenizer.TagName()
			tag := string(name)
			if tag == "script" || tag == "style" {
				if skip > 0 {
					skip--
				}
				continue
			}
			if skip > 0 {
				continue
			}
			switch tag {
			case "p", "div", "li":
				result.WriteByte('\n')
			case "b", "strong":
				if markdown {
					result.WriteString("**")
				}
			}
		}
	}
}
