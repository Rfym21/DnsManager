package dns

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fixtureProvider(t *testing.T, kind string, cfg Config, zone, name string, handler http.HandlerFunc) Provider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	p, err := NewWithOptions(kind, cfg, zone, name, FactoryOptions{Client: srv.Client(), Endpoint: srv.URL, Now: func() time.Time { return time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestCloudflareIDNWriteAndErrors(t *testing.T) {
	calls := 0
	p := fixtureProvider(t, "cloudflare", Config{"apikey": "fixture", "auth": "0", "email": "test@example.invalid"}, "zone", "例子.com", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Auth-Key") != "fixture" || r.Header.Get("Authorization") != "" {
			t.Error("incorrect legacy auth")
		}
		if r.Method == "POST" {
			var b map[string]any
			if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
				t.Error(err)
			}
			if b["name"] != "_acme-challenge.xn--fsqu00a.com" || b["content"] != "challenge\"payload" || b["ttl"] != float64(1) {
				t.Errorf("unexpected body: %#v", b)
			}
			fmt.Fprint(w, `{"success":true,"result":{"id":"r1","name":"_acme-challenge.xn--fsqu00a.com","type":"TXT","content":"challenge\"payload","ttl":1,"proxied":false}}`)
			return
		}
		w.WriteHeader(429)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":1015,"message":"rate limited"}]}`)
	})
	r, err := p.CreateRecord(context.Background(), Record{Name: "_acme-challenge", Type: "TXT", Value: "challenge\"payload", TTL: 1, Enabled: true})
	if err != nil || r.Name != "_acme-challenge" {
		t.Fatalf("record %#v err %v", r, err)
	}
	_, err = p.GetRecord(context.Background(), "r1")
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Status != 429 || remote.Code != "1015" || remote.Message != "rate limited" {
		t.Fatalf("expected remote error: %v", err)
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}
func TestAliyunSignatureAndDNSPodPagination(t *testing.T) {
	p := fixtureProvider(t, "aliyun", Config{"AccessKeyId": "id", "AccessKeySecret": "secret"}, "", "example.com", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		signature := r.Form.Get("Signature")
		r.Form.Del("Signature")
		want := hmac1("secret&", "POST&%2F&"+percent(strings.ReplaceAll(r.Form.Encode(), "+", "%20")))
		if signature != want {
			t.Error("incorrect Aliyun RPC signature")
		}
		if r.Form.Get("PageNumber") != "3" || r.Form.Get("PageSize") != "7" {
			t.Error("pagination not forwarded")
		}
		fmt.Fprint(w, `{"TotalCount":21,"Domains":{"Domain":[{"DomainId":"123","DomainName":"example.com","RecordCount":1}]}}`)
	})
	page, err := p.ListDomains(context.Background(), ListOptions{Page: 3, PageSize: 7})
	if err != nil || page.Total != 21 || page.Rows[0].ID != "123" {
		t.Fatalf("%#v %v", page, err)
	}
	p = fixtureProvider(t, "dnspod", Config{"SecretId": "id", "SecretKey": "secret"}, "", "example.com", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "TC3-HMAC-SHA256 Credential=id/") {
			t.Error("signature missing")
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["Offset"] != float64(14) || b["Limit"] != float64(7) || r.Header.Get("X-TC-Action") != "DescribeDomainList" {
			t.Errorf("%#v", b)
		}
		fmt.Fprint(w, `{"Response":{"DomainCountInfo":{"DomainTotal":21},"DomainList":[{"DomainId":123,"Name":"example.com"}]}}`)
	})
	page, err = p.ListDomains(context.Background(), ListOptions{Page: 3, PageSize: 7})
	if err != nil || page.Rows[0].ID != "123" {
		t.Fatal(page, err)
	}
}
func TestPowerDNSPreservesRRSetSiblingAndComment(t *testing.T) {
	var patch struct {
		Sets []pdSet `json:"rrsets"`
	}
	p := fixtureProvider(t, "powerdns", Config{"apikey": "fixture"}, "example.com.", "example.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			fmt.Fprint(w, `{"rrsets":[{"name":"www.example.com.","type":"A","ttl":300,"records":[{"content":"192.0.2.1","disabled":false},{"content":"192.0.2.2","disabled":false}],"comments":[{"account":"admin","content":"keep"}]}]}`)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			t.Error(err)
		}
		w.WriteHeader(204)
	})
	err := p.DeleteRecord(context.Background(), setID("www.example.com.", "A", "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(patch.Sets) != 1 || len(patch.Sets[0].Records) != 1 || patch.Sets[0].Records[0].Content != "192.0.2.2" || len(patch.Sets[0].Comments) != 1 || patch.Sets[0].Comments[0].Content != "keep" {
		t.Fatalf("lost RRSet sibling/metadata: %#v", patch)
	}
}
func TestRoute53MarkerAndSiblingWrite(t *testing.T) {
	var changes struct {
		Changes []awsChange `xml:"ChangeBatch>Changes>Change"`
	}
	p := fixtureProvider(t, "aws", Config{"AccessKeyId": "id", "SecretAccessKey": "secret"}, "Z1", "example.com", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			t.Error("signature missing")
		}
		if r.URL.Path == "/hostedzone" {
			if r.URL.Query().Get("marker") == "" {
				fmt.Fprint(w, `<ListHostedZonesResponse><HostedZones><HostedZone><Id>/hostedzone/Z1</Id><Name>example.com.</Name></HostedZone></HostedZones><IsTruncated>true</IsTruncated><NextMarker>next</NextMarker></ListHostedZonesResponse>`)
			} else {
				fmt.Fprint(w, `<ListHostedZonesResponse><HostedZones><HostedZone><Id>/hostedzone/Z2</Id><Name>other.example.</Name></HostedZone></HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesResponse>`)
			}
			return
		}
		if r.Method == "GET" {
			fmt.Fprint(w, `<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>www.example.com.</Name><Type>A</Type><TTL>300</TTL><ResourceRecords><ResourceRecord><Value>192.0.2.1</Value></ResourceRecord><ResourceRecord><Value>192.0.2.2</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if err := xml.Unmarshal(body, &changes); err != nil {
			t.Error(err)
		}
		fmt.Fprint(w, `<ChangeResourceRecordSetsResponse><ChangeInfo><Id>change</Id></ChangeInfo></ChangeResourceRecordSetsResponse>`)
	})
	page, err := p.ListDomains(context.Background(), ListOptions{PageSize: 20})
	if err != nil || page.Total != 2 || page.Rows[1].ID != "Z2" {
		t.Fatal(page, err)
	}
	r, err := p.UpdateRecord(context.Background(), setID("www", "A", "192.0.2.1"), Record{Name: "www", Type: "A", Value: "192.0.2.3", TTL: 600, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Value != "192.0.2.3" || len(changes.Changes) != 1 || len(changes.Changes[0].Set.Values) != 2 || changes.Changes[0].Set.Values[1] != "192.0.2.2" {
		t.Fatalf("lost sibling: %#v", changes)
	}
}
func TestCatalogAndValidation(t *testing.T) {
	list := Metadata()
	if len(list) != 22 {
		t.Fatal(len(list))
	}
	for _, d := range list {
		p, err := New(d.ID, Config{}, "", "example.com")
		if d.Implemented && (err != nil || p == nil) {
			t.Errorf("claimed missing implementation %s", d.ID)
		}
	}
	if ValidateRecord(Record{Name: "www", Type: "A", Value: "2001:db8::1", TTL: 300}, "example.com") == nil {
		t.Error("accepted invalid IPv4")
	}
	if _, err := CanonicalName("例子.com"); err != nil {
		t.Fatal(err)
	}
}

func TestCloudflareCRUDAndPauseRoot(t *testing.T) {
	record := map[string]any{"id": "r1", "name": "example.com", "type": "A", "content": "192.0.2.1", "ttl": 300, "proxied": false}
	p := fixtureProvider(t, "cloudflare", Config{"apikey": "key", "auth": "1"}, "zone", "example.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer key" {
			t.Error("CF token missing")
		}
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/dns_records") {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{record}, "result_info": map[string]any{"total_count": 1}})
			return
		}
		if r.Method == "PATCH" || r.Method == "POST" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			for k, v := range body {
				record[k] = v
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": record})
	})
	ctx := context.Background()
	if _, err := p.ListRecords(ctx, ListOptions{}); err != nil {
		t.Fatal(err)
	}
	r := Record{Name: "@", Type: "A", Value: "192.0.2.1", TTL: 300, Enabled: true}
	if _, err := p.CreateRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpdateRecord(ctx, "r1", r); err != nil {
		t.Fatal(err)
	}
	if err := p.SetStatus(ctx, "r1", false); err != nil {
		t.Fatal(err)
	}
	if record["name"] != "__root___pause.example.com" {
		t.Fatal(record)
	}
	if err := p.SetStatus(ctx, "r1", true); err != nil {
		t.Fatal(err)
	}
	if record["name"] != "example.com" {
		t.Fatal(record)
	}
	if err := p.SetRemark(ctx, "r1", "remark"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteRecord(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
}

func TestRejectUnsupportedStatusBeforeRemoteWrite(t *testing.T) {
	for _, kind := range []string{"aws", "dynv6", "namesilo", "spaceship", "henet", "aliyunesa"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			p := fixtureProvider(t, kind, Config{}, "zone", "example.com", func(w http.ResponseWriter, r *http.Request) { calls++ })
			_, err := p.CreateRecord(context.Background(), Record{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 300, Enabled: false})
			if !errors.Is(err, ErrCapability) || calls != 0 {
				t.Fatal(err, calls)
			}
		})
	}
}

func TestMetadataIsolationAndRecordNames(t *testing.T) {
	catalog := Metadata()
	catalog[0].Fields[2].Options[0].Label = "modified"
	if Metadata()[0].Fields[2].Options[0].Label == "modified" {
		t.Error("metadata mutable alias")
	}
	for _, name := range []string{"_acme challenge", "bad/name", ".example.com", "-bad", "bad..name"} {
		if _, err := asciiRecordName(name, "example.com"); err == nil {
			t.Error("accepted invalid name", name)
		}
	}
}

func TestProviderRemoteErrorProtocols(t *testing.T) {
	for _, kind := range []string{"aliyun", "dnspod", "huawei", "baidu", "huoshan", "jdcloud", "aws", "dynv6", "spaceship", "dnsla", "namesilo", "west", "dnsmgr", "goedge", "technitium", "bt", "qingcloud", "henet", "aliyunesa", "tencenteo", "powerdns"} {
		t.Run(kind, func(t *testing.T) {
			cfg := Config{"AccessKeyId": "id", "AccessKeySecret": "secret", "SecretAccessKey": "secret", "SecretId": "id", "SecretKey": "secret", "apikey": "key", "token": "token", "access_key_id": "id", "secret_access_key": "secret", "username": "user", "password": "pass", "nsClusterId": "1"}
			p := fixtureProvider(t, kind, cfg, "1", "example.com", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
				switch kind {
				case "aws":
					fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>denied</Message></Error></ErrorResponse>`)
				case "dnspod", "tencenteo":
					fmt.Fprint(w, `{"Response":{"Error":{"Code":"AccessDenied","Message":"denied"}}}`)
				case "huoshan":
					fmt.Fprint(w, `{"ResponseMetadata":{"Error":{"Code":"AccessDenied","Message":"denied"}}}`)
				case "jdcloud":
					fmt.Fprint(w, `{"error":{"code":"AccessDenied","message":"denied"}}`)
				case "huawei":
					fmt.Fprint(w, `{"error_msg":"denied","error_code":"AccessDenied"}`)
				default:
					fmt.Fprint(w, `{"Code":"AccessDenied","Message":"denied","message":"denied","error":"denied","code":403,"msg":"denied","status":"error","errorMessage":"denied"}`)
				}
			})
			_, err := p.ListDomains(context.Background(), ListOptions{})
			if err == nil {
				t.Error("accepted remote denial")
			}
		})
	}
}

func TestPowerDNSCRUDAndStatuses(t *testing.T) {
	sets := []pdSet{{Name: "www.example.com.", Type: "A", TTL: 300, Records: []pdRecord{{Content: "192.0.2.1"}}}}
	p := fixtureProvider(t, "powerdns", Config{"apikey": "key"}, "example.com.", "example.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]any{"rrsets": sets})
			return
		}
		var patch struct {
			Sets []pdSet `json:"rrsets"`
		}
		_ = json.NewDecoder(r.Body).Decode(&patch)
		for _, set := range patch.Sets {
			index := -1
			for i, s := range sets {
				if s.Name == set.Name && s.Type == set.Type {
					index = i
					break
				}
			}
			if set.Change == "DELETE" {
				if index >= 0 {
					sets = append(sets[:index], sets[index+1:]...)
				}
			} else if index >= 0 {
				sets[index] = set
			} else {
				sets = append(sets, set)
			}
		}
		w.WriteHeader(204)
	})
	ctx := context.Background()
	r := Record{Name: "www", Type: "A", Value: "192.0.2.2", TTL: 300, Enabled: true}
	created, err := p.CreateRecord(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Value = "192.0.2.3"
	updated, err := p.UpdateRecord(ctx, created.ID, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.SetStatus(ctx, updated.ID, false); err != nil {
		t.Fatal(err)
	}
	if err = p.SetRemark(ctx, updated.ID, "keep"); err != nil {
		t.Fatal(err)
	}
	got, err := p.GetRecord(ctx, updated.ID)
	if err != nil || got.Enabled || got.Remark != "keep" {
		t.Fatal(got, err)
	}
	if err = p.DeleteRecord(ctx, updated.ID); err != nil {
		t.Fatal(err)
	}
	if len(sets[0].Records) != 1 || sets[0].Records[0].Content != "192.0.2.1" {
		t.Fatal(sets)
	}
}

func TestRoute53CRUDProtocol(t *testing.T) {
	sets := []awsSet{{Name: "www.example.com.", Type: "A", TTL: 300, Values: []string{"192.0.2.1"}}}
	p := fixtureProvider(t, "aws", Config{"AccessKeyId": "id", "SecretAccessKey": "secret"}, "Z1", "example.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_ = xml.NewEncoder(w).Encode(awsList{Sets: sets})
			return
		}
		var request struct {
			Changes []awsChange `xml:"ChangeBatch>Changes>Change"`
		}
		_ = xml.NewDecoder(r.Body).Decode(&request)
		for _, c := range request.Changes {
			index := -1
			for i, s := range sets {
				if s.Name == c.Set.Name && s.Type == c.Set.Type {
					index = i
					break
				}
			}
			if c.Action == "DELETE" {
				if index >= 0 {
					sets = append(sets[:index], sets[index+1:]...)
				}
			} else if index >= 0 {
				sets[index] = c.Set
			} else {
				sets = append(sets, c.Set)
			}
		}
		fmt.Fprint(w, `<ChangeResourceRecordSetsResponse/>`)
	})
	ctx := context.Background()
	created, err := p.CreateRecord(ctx, Record{Name: "www", Type: "A", Value: "192.0.2.2", TTL: 300, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.GetRecord(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if err = p.DeleteRecord(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if len(sets[0].Values) != 1 || sets[0].Values[0] != "192.0.2.1" {
		t.Fatal(sets)
	}
}

func TestCloudflareDomainPaginationLimit(t *testing.T) {
	p := fixtureProvider(t, "cloudflare", Config{"apikey": "key", "auth": "1"}, "", "example.com", func(w http.ResponseWriter, r *http.Request) {
		page := 1
		if r.URL.Query().Get("page") == "2" {
			page = 2
		}
		rows := []any{}
		for i := (page - 1) * 50; i < min(page*50, 73); i++ {
			rows = append(rows, map[string]any{"id": fmt.Sprint(i), "name": fmt.Sprintf("d%d.example", i)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rows, "result_info": map[string]any{"total_count": 73}})
	})
	page, err := p.ListDomains(context.Background(), ListOptions{Page: 2, PageSize: 40})
	if err != nil || page.Total != 73 || len(page.Rows) != 33 || page.Rows[0].ID != "40" || page.Rows[32].ID != "72" {
		t.Fatal(page, err)
	}
}
