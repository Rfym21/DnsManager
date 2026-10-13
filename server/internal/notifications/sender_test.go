package notifications

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookTemplateAndRejection(t *testing.T) {
	var payload map[string]any
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{\"errcode\":0}"))
	}))
	defer remote.Close()
	channel := Channel{Provider: "custom_webhook", Config: map[string]string{"url": remote.URL, "body_template": `{"message":"{{title}}: {{content}}"}`}}
	if err := (Sender{}).Send(context.Background(), channel, Message{Title: "quoted\"title", Body: "new\nline"}); err != nil {
		t.Fatal(err)
	}
	if payload["message"] != "quoted\"title: new\nline" {
		t.Fatal(payload)
	}
	failure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{\"errcode\":123}")) }))
	defer failure.Close()
	channel.Config["url"] = failure.URL
	if err := (Sender{}).Send(context.Background(), channel, Message{}); err == nil {
		t.Fatal("channel error must not be reported delivered")
	}
}
