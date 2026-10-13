package dns

import "testing"

func TestDesiredEqualComparesEntireRRsetAndOptionalNumbers(t *testing.T) {
	n := 10
	a := Record{Name: "_sip", Type: "SRV", Value: "v1", Values: []string{"v1", "v2"}, TTL: 300, Priority: &n, Weight: &n}
	b := a
	b.Values = []string{"v2", "v1"}
	b.Line = "default"
	if !DesiredEqual(a, b) {
		t.Fatal("order affected tuple")
	}
	b.Values = []string{"v1"}
	if DesiredEqual(a, b) {
		t.Fatal("partial RRset confirmed")
	}
	b = a
	b.Weight = nil
	if DesiredEqual(a, b) {
		t.Fatal("different weight confirmed")
	}
	b = a
	b.Priority = nil
	if DesiredEqual(a, b) {
		t.Fatal("different priority confirmed")
	}
}

func TestRemoteErrorNeverEchoesProviderMessageOrCode(t *testing.T) {
	e := &RemoteError{Provider: "fixture", Status: 403, Message: "fixture-secret", Code: "fixture-secret"}
	if e.Error() != "fixture: DNS request rejected (HTTP 403)" {
		t.Fatal(e.Error())
	}
}
