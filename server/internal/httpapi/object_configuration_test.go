package httpapi

import (
	"encoding/json"
	"testing"
)

func TestConfigurationCannotForgeIssuedStateOrLoseCheckpoint(t *testing.T) {
	before := json.RawMessage(`{"account_id":"issuer","domains":["example.com"],"status":"issued","fingerprint":"real","private_key":"private","checkpoint":{"stage":"issued"},"metadata":{"source":"fixture"}}`)
	incoming := json.RawMessage(`{"account_id":"issuer","domains":["example.com"],"auto_renew":true,"status":"forged","fingerprint":"fake","checkpoint":{},"private_key":"stolen","metadata":{"source":"forged"}}`)
	raw, err := configurationData("certificates", before, incoming)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	json.Unmarshal(raw, &d)
	if d["status"] != "issued" || d["fingerprint"] != "real" || d["private_key"] != "private" || d["auto_renew"] != true {
		t.Fatal("runtime data overwritten", string(raw))
	}
	if d["checkpoint"].(map[string]any)["stage"] != "issued" || d["metadata"].(map[string]any)["source"] != "fixture" {
		t.Fatal(string(raw))
	}
	raw, err = configurationData("certificates", nil, incoming)
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(raw, &d)
	var created map[string]any
	json.Unmarshal(raw, &created)
	if _, ok := created["status"]; ok {
		t.Fatal("new cloud certificate accepted forged status")
	}
}
