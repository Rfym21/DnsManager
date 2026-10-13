package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestProtocolMutationResponsesRemainUnknown(t *testing.T) {
	for _, protocol := range []string{"common", "rest", "ali", "tencent", "signed", "form", "namesilo-get", "bt", "technitium", "goedge", "aws", "powerdns", "henet"} {
		t.Run(protocol, func(t *testing.T) {
			for _, tc := range []struct {
				status  int
				body    string
				unknown bool
			}{{200, "not-json-or-xml", true}, {200, "null", true}, {200, "{} {}", true}, {502, "not-json-or-xml", true}, {503, `{"message":"fixture-secret","code":"fixture-secret"}`, true}, {403, "not-json-or-xml", false}, {429, `{"message":"fixture-secret","code":"fixture-secret"}`, false}} {
				t.Run(fmt.Sprint(tc.status, "-", tc.body), func(t *testing.T) {
					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
					defer srv.Close()
					b := &base{kind: "fixture", cfg: Config{"AccessKeyId": "fixture", "AccessKeySecret": "fixture", "SecretAccessKey": "fixture", "SecretId": "fixture", "SecretKey": "fixture", "apikey": "fixture", "token": "fixture"}, endpoint: srv.URL, client: srv.Client(), now: time.Now}
					ctx := context.Background()
					var err error
					switch protocol {
					case "common":
						_, _, err = b.json(ctx, "POST", "/record", nil, map[string]any{}, nil)
					case "rest":
						b.kind = "dynv6"
						_, err = (&restProvider{b}).request(ctx, "POST", "/record", nil, map[string]any{})
					case "ali":
						b.kind = "aliyun"
						_, err = (&rpcProvider{b}).call(ctx, "AddDomainRecord", map[string]any{})
					case "tencent":
						b.kind = "dnspod"
						_, err = (&rpcProvider{b}).call(ctx, "CreateRecord", map[string]any{})
					case "signed":
						b.kind = "huawei"
						_, err = b.signed(ctx, "POST", "/record", nil, map[string]any{})
					case "form":
						b.kind = "west"
						_, err = (&formProvider{b}).call(ctx, "/domain/", url.Values{"act": {"adddnsrecord"}})
					case "namesilo-get":
						b.kind = "namesilo"
						_, err = (&formProvider{b}).call(ctx, "/dnsAddRecord", nil)
					case "bt":
						_, err = (&btDNS{b}).call(ctx, "/api/v1/dns/record/create", map[string]any{})
					case "technitium":
						_, err = (&technitium{b}).call(ctx, "POST", "/zones/records/add", nil)
					case "goedge":
						_, err = (&goEdge{base: b, token: "fixture"}).call(ctx, "/NSRecordService/createNSRecord", nil)
					case "aws":
						_, err = (&route53{b}).request(ctx, "POST", "/record", nil, nil)
					case "powerdns":
						_, err = (&powerDNS{base: b}).request(ctx, "PATCH", "/record", map[string]any{})
					case "henet":
						_, err = (&heDNS{base: b}).rawHTML(ctx, "POST", "/record", nil)
					}
					// HE's successful HTML body is interpreted by the write confirmation,
					// not rawHTML. AWS valid XML and PowerDNS empty PATCH are also permitted.
					if protocol == "henet" && tc.status == 200 {
						return
					}
					var remote *RemoteError
					if !errors.As(err, &remote) || remote.UnknownResult != tc.unknown {
						t.Fatalf("unknown=%v error=%#v", tc.unknown, err)
					}
					if strings.Contains(err.Error(), "fixture-secret") {
						t.Fatal("remote body leaked", err)
					}
				})
			}
		})
	}
}

func TestRPCReadFailuresNeverClaimDNSMutation(t *testing.T) {
	for _, kind := range []string{"aliyun", "dnspod", "namesilo", "west", "bt", "goedge"} {
		t.Run(kind, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502); fmt.Fprint(w, "invalid") }))
			defer srv.Close()
			b := &base{kind: kind, cfg: Config{"AccessKeyId": "fixture", "AccessKeySecret": "fixture", "SecretId": "fixture", "SecretKey": "fixture"}, endpoint: srv.URL, client: srv.Client(), now: time.Now}
			var err error
			switch kind {
			case "aliyun", "dnspod":
				_, err = (&rpcProvider{b}).call(context.Background(), "DescribeDomainList", nil)
			case "namesilo":
				_, err = (&formProvider{b}).call(context.Background(), "/dnsListRecords", nil)
			case "west":
				_, err = (&formProvider{b}).call(context.Background(), "/domain/", url.Values{"act": {"getdnsrecord"}})
			case "bt":
				_, err = (&btDNS{b}).call(context.Background(), "/api/v1/dns/record/list", nil)
			case "goedge":
				_, err = (&goEdge{base: b, token: "fixture"}).call(context.Background(), "/NSRecordService/listNSRecords", nil)
			}
			var remote *RemoteError
			if !errors.As(err, &remote) || remote.UnknownResult {
				t.Fatalf("read misclassified: %#v", err)
			}
		})
	}
}

type truncatedDNSBody struct{ sent bool }

func (b *truncatedDNSBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, `{"accepted":true}`), nil
	}
	return 0, io.ErrUnexpectedEOF
}
func (b *truncatedDNSBody) Close() error { return nil }

type dnsRoundTripFunc func(*http.Request) (*http.Response, error)

func (f dnsRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestDNSResponseReadLossUsesKnownHTTPRejection(t *testing.T) {
	for _, status := range []int{200, 403, 502} {
		b := &base{kind: "fixture", endpoint: "http://fixture.invalid", client: &http.Client{Transport: dnsRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: &truncatedDNSBody{}, Header: http.Header{}}, nil
		})}}
		_, _, err := b.raw(context.Background(), "POST", "/", nil, nil, nil)
		var remote *RemoteError
		if !errors.As(err, &remote) || remote.UnknownResult != (status != 403) {
			t.Fatalf("status %d error %#v", status, err)
		}
	}
}

func TestAcceptedCreateFollowupFailureRemainsUnknown(t *testing.T) {
	for _, kind := range []string{"aliyun", "dnspod", "west", "bt", "huawei", "jdcloud", "huoshan", "qingcloud"} {
		t.Run(kind, func(t *testing.T) {
			mutation := false
			p := fixtureProvider(t, kind, Config{"AccessKeyId": "fixture", "AccessKeySecret": "fixture", "SecretAccessKey": "fixture", "SecretId": "fixture", "SecretKey": "fixture", "access_key_id": "fixture", "secret_access_key": "fixture"}, "1", "example.com", func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				action := r.Form.Get("Action")
				if action == "" {
					action = r.Header.Get("X-TC-Action")
				}
				write := r.Method != "GET" && !strings.HasPrefix(action, "Describe") && !strings.HasPrefix(action, "List") && !strings.HasPrefix(action, "Get")
				if !mutation && write {
					mutation = true
					switch kind {
					case "aliyun":
						fmt.Fprint(w, `{"RecordId":"1"}`)
					case "dnspod":
						fmt.Fprint(w, `{"Response":{"RecordId":1}}`)
					case "west":
						fmt.Fprint(w, `{"result":200,"data":{"id":"1"}}`)
					case "bt":
						fmt.Fprint(w, `{"code":0,"data":{"id":"1"}}`)
					case "huawei":
						fmt.Fprint(w, `{"id":"1"}`)
					case "jdcloud":
						fmt.Fprint(w, `{"result":{"data":{"id":"1"}}}`)
					case "huoshan":
						fmt.Fprint(w, `{"Result":{"RecordID":"1"}}`)
					case "qingcloud":
						fmt.Fprint(w, `{"domain_record_id":"1"}`)
					}
					return
				}
				w.WriteHeader(403)
				fmt.Fprint(w, `{"message":"follow-up rejected"}`)
			})
			_, err := p.CreateRecord(context.Background(), Record{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 300, Line: "default", Enabled: false})
			var remote *RemoteError
			if !mutation || !errors.As(err, &remote) || !remote.UnknownResult {
				t.Fatalf("kind %s mutation %v error %#v", kind, mutation, err)
			}
		})
	}
}

func TestHuaweiSingleValueEditPreservesRRsetSiblings(t *testing.T) {
	for _, typ := range []string{"A", "MX"} {
		t.Run(typ, func(t *testing.T) {
			writes := 0
			values := []string{"192.0.2.1", "192.0.2.2"}
			value := "192.0.2.3"
			var priority *int
			if typ == "MX" {
				values = []string{"10 one.example.com", "10 two.example.com"}
				value = "three.example.com"
				n := 10
				priority = &n
			}
			p := fixtureProvider(t, "huawei", Config{"AccessKeyId": "fixture", "SecretAccessKey": "fixture"}, "1", "example.com", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					_ = json.NewEncoder(w).Encode(map[string]any{"id": "r1", "name": "www.example.com.", "type": typ, "records": values, "ttl": 300, "line": "default_view", "status": "ACTIVE"})
					return
				}
				if r.URL.Path == "/v2.1/zones/1/recordsets/r1" {
					writes++
					var b map[string]any
					_ = json.NewDecoder(r.Body).Decode(&b)
					got := stringValues(b, "records")
					want := []string{value, values[1]}
					if typ == "MX" {
						want[0] = "10 " + value
					}
					if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
						t.Fatalf("siblings lost: %#v", b)
					}
				}
				fmt.Fprint(w, `{"id":"r1"}`)
			})
			_, err := p.UpdateRecord(context.Background(), "r1", Record{Name: "www", Type: typ, Value: value, TTL: 300, Enabled: true, Priority: priority})
			if err != nil || writes != 1 {
				t.Fatalf("writes %d err %v", writes, err)
			}
		})
	}
}

func TestMixedHuaweiMXAndSharedQingcloudRenameCannotDiscardSiblings(t *testing.T) {
	for _, kind := range []string{"huawei", "qingcloud"} {
		t.Run(kind, func(t *testing.T) {
			writes := 0
			p := fixtureProvider(t, kind, Config{"AccessKeyId": "fixture", "SecretAccessKey": "fixture", "access_key_id": "fixture", "secret_access_key": "fixture"}, "1", "example.com", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					writes++
					fmt.Fprint(w, `{}`)
					return
				}
				if kind == "huawei" {
					fmt.Fprint(w, `{"id":"r1","name":"www.example.com.","type":"MX","records":["10 one.example.com","20 two.example.com"],"ttl":300,"status":"ACTIVE"}`)
				} else {
					fmt.Fprint(w, `{"data":{"domain_name":"www.example.com.","rd_type":"A","view_id":0,"record":[{"data":[{"record_value_id":"1","value":"192.0.2.1","status":1},{"record_value_id":"2","value":"192.0.2.2","status":1}]}]}}`)
				}
			})
			r := Record{Name: "renamed", Type: "A", Value: "192.0.2.3", TTL: 300, Enabled: true}
			id := "7_1"
			if kind == "huawei" {
				n := 10
				r.Name = "www"
				r.Type = "MX"
				r.Value = "three.example.com"
				r.Priority = &n
				id = "r1"
			}
			_, err := p.UpdateRecord(context.Background(), id, r)
			if err == nil || writes != 0 {
				t.Fatalf("writes=%d err=%v", writes, err)
			}
		})
	}
}

func TestObserveRenameDoesNotConfirmWhileOldRecordRemains(t *testing.T) {
	p := fixtureProvider(t, "dynv6", Config{"token": "fixture"}, "zone", "example.com", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"id":"old","name":"old","type":"A","data":"192.0.2.1"},{"id":"new","name":"new","type":"A","data":"192.0.2.2"}]`)
	})
	_, confirmed, err := ObserveMutation(context.Background(), p, "update", Record{ID: "old", Name: "new", Type: "A", Value: "192.0.2.2", TTL: 0, Enabled: true})
	if err != nil || confirmed {
		t.Fatalf("confirmed=%v err=%v", confirmed, err)
	}
}

func TestNameSiloUpdateUsesReturnedChangedID(t *testing.T) {
	p := fixtureProvider(t, "namesilo", Config{"apikey": "fixture"}, "zone", "example.com", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"reply":{"code":300,"record_id":"changed-id"}}`)
	})
	r, err := p.UpdateRecord(context.Background(), "old-id", Record{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 300, Enabled: true})
	if err != nil || r.ID != "changed-id" {
		t.Fatalf("ID=%s err=%v", r.ID, err)
	}
}
