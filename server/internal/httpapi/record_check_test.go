package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	mdns "github.com/miekg/dns"
)

func TestRecordDoHWireQueryAndValueSemantics(t *testing.T) {
	var requestName string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			t.Error("DoH wire protocol missing")
		}
		raw, _ := io.ReadAll(r.Body)
		query := new(mdns.Msg)
		if query.Unpack(raw) != nil {
			t.Fatal("bad DNS query")
		}
		requestName = query.Question[0].Name
		answer := new(mdns.Msg)
		answer.SetReply(query)
		switch query.Question[0].Qtype {
		case mdns.TypeAAAA:
			answer.Answer = []mdns.RR{&mdns.AAAA{Hdr: mdns.RR_Header{Name: requestName, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")}}
		case mdns.TypeTXT:
			answer.Answer = []mdns.RR{&mdns.TXT{Hdr: mdns.RR_Header{Name: requestName, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60}, Txt: []string{"Case", "Sensitive"}}}
		default:
			answer.Rcode = mdns.RcodeNameError
		}
		raw, _ = answer.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(raw)
	}))
	defer server.Close()
	a := &API{DoHClient: server.Client(), DoHEndpoint: server.URL}
	req := httptest.NewRequest(http.MethodGet, "http://local", nil)
	result, err := a.checkRecordDNS(req, dns.Record{Type: "AAAA", Value: "2001:0db8:0:0:0:0:0:1"}, "www.example.invalid", mdns.TypeAAAA)
	if err != nil || result.Status != "active" || !result.Matched || requestName != "www.example.invalid." || len(result.Answers) != 1 {
		t.Fatal(result, err, requestName)
	}
	result, err = a.checkRecordDNS(req, dns.Record{Type: "TXT", Value: "casesensitive"}, "txt.example.invalid", mdns.TypeTXT)
	if err != nil || result.Status != "mismatch" || result.Matched || result.Answers[0].Value != "CaseSensitive" {
		t.Fatal("TXT case or chunks lost", result, err)
	}
	if recordValuesMatch(dns.Record{Type: "TXT", Values: []string{"first", "second"}}, []string{"first"}) {
		t.Fatal("partial RRset called fully propagated")
	}
	if !recordValuesMatch(dns.Record{Type: "CNAME", Value: "ORIGIN.example.invalid."}, []string{"origin.example.invalid"}) {
		t.Fatal("CNAME normalization lost")
	}
	result, err = a.checkRecordDNS(req, dns.Record{Type: "A", Value: "192.0.2.1"}, "absent.example.invalid", mdns.TypeA)
	if err != nil || result.Status != "not_found" || result.RCode != mdns.RcodeNameError {
		t.Fatal(result, err)
	}
}

type recordDetailFixture struct {
	dns.Provider
	calls int
}

func (p *recordDetailFixture) GetRecord(context.Context, string) (dns.Record, error) {
	p.calls++
	return dns.Record{ID: "fixture-record", Name: "www", Type: "A", Value: "192.0.2.1", TTL: 60, Enabled: true}, nil
}
func TestRecordDetailAndCheckRequireDomainReadPermission(t *testing.T) {
	f := newLegacyFixture(t)
	a := f.a
	provider := &recordDetailFixture{}
	a.DNSFactory = func(string, map[string]string, string, string) (dns.Provider, error) { return provider, nil }
	_, adminToken, adminCSRF := testUser(t, a, "admin")
	_, restrictedToken, _ := testUser(t, a, "restricted")
	base := "/api/v1/domains/" + f.domain.ID + "/records/fixture-record"
	for _, path := range []string{base, base + "/check"} {
		response := requestAPI(a, http.MethodGet, path, restrictedToken, "", nil)
		if response.Code != http.StatusForbidden || provider.calls != 0 {
			t.Fatal("record read permission bypassed", response.Code, provider.calls)
		}
	}
	response := requestAPI(a, http.MethodGet, base, adminToken, adminCSRF, nil)
	var result struct {
		Record dns.Record `json:"record"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Record.Version == "" || result.Record.ID != "fixture-record" {
		t.Fatal("detail did not return current record version", response.Code, response.Body.String())
	}
	// Suppress remote access while verifying authorized checks use server-side
	// current names instead of arbitrary client-supplied lookup parameters.
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer remote.Close()
	a.DoHEndpoint, a.DoHClient = remote.URL, remote.Client()
	response = requestAPI(a, http.MethodGet, base+"/check?name=attacker.invalid", adminToken, adminCSRF, nil)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "attacker.invalid") {
		t.Fatal("check did not use configured DNS record", response.Code, response.Body.String())
	}
}
