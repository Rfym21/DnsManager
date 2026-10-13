package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestQingcloudGroupProtocol(t *testing.T) {
	group := map[string]any{"domain_record_id": "7", "domain_name": "www.example.com.", "zone_name": "example.com.", "rd_type": "A", "view_id": 0, "ttl": 300, "mode": 3, "record": []any{map[string]any{"weight": 2, "data": []any{map[string]any{"record_value_id": "1", "value": "192.0.2.1", "status": 1}, map[string]any{"record_value_id": "2", "value": "192.0.2.2", "status": 1}}}}}
	writes := 0
	p := fixtureProvider(t, "qingcloud", Config{"access_key_id": "id", "secret_access_key": "secret"}, "example.com.", "example.com", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "QC-HMAC-SHA256 id:") {
			t.Error("QC auth missing")
		}
		out := map[string]any{"code": 0}
		switch r.URL.Path {
		case "/v1/user/zones":
			out["zones"] = []any{map[string]any{"zone_name": "example.com."}}
			out["total_count"] = 1
		case "/v1/dns/host_info/":
			out["records"] = []any{group}
		case "/v1/zone/view/":
			out["zone_views"] = []any{map[string]any{"id": 0, "name": "*"}}
		case "/v1/record/":
			out["domain_record_id"] = "7"
		case "/v1/dr_id/7":
			if r.Method == "GET" {
				out["data"] = group
			} else {
				writes++
				var b map[string]any
				_ = json.NewDecoder(r.Body).Decode(&b)
				var groups []map[string]any
				_ = json.Unmarshal([]byte(str(b, "record")), &groups)
				values := arr(groups[0], "values")
				if writes == 1 && (len(values) != 2 || str(values[1], "value") != "192.0.2.2" || str(values[0], "value") != "192.0.2.3") {
					t.Error("QC update lost sibling", b)
				}
				if writes == 2 && (len(values) != 1 || str(values[0], "value") != "192.0.2.2") {
					t.Error("QC delete lost sibling", b)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	ctx := context.Background()
	if _, err := p.ListDomains(ctx, ListOptions{}); err != nil {
		t.Fatal(err)
	}
	page, err := p.ListRecords(ctx, ListOptions{Name: "www"})
	if err != nil || page.Total != 2 {
		t.Fatal(page, err)
	}
	if _, err = p.GetRecord(ctx, "7_1"); err != nil {
		t.Fatal(err)
	}
	r := Record{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 300, Enabled: true}
	if _, err = p.CreateRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Value = "192.0.2.3"
	if _, err = p.UpdateRecord(ctx, "7_1", r); err != nil {
		t.Fatal(err)
	}
	if err = p.DeleteRecord(ctx, "7_1"); err != nil {
		t.Fatal(err)
	}
	if err = p.SetStatus(ctx, "7_1", false); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Lines(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestHENativeSessionHTMLProtocol(t *testing.T) {
	login := 0
	writes := 0
	domains := `<input value="12" name="example.com" onclick="delete_dom(this);"><a href="index.cgi?hosted_dns_zoneid=12&amp;menu=edit_zone">example.com</a>`
	record := `<table><tr class="dns_tr"><td><input type="checkbox"></td><td>42</td><td>txt.example.com</td><td>TXT</td><td>300</td><td></td><td>&quot;a,b&quot;</td></tr></table>`
	p := fixtureProvider(t, "henet", Config{"username": "fixture-user", "password": "fixture-password"}, "12", "example.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/" {
			_ = r.ParseForm()
			if r.Form.Get("email") != "fixture-user" || r.Form.Get("pass") != "fixture-password" {
				t.Error("HE login malformed")
			}
			login++
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "fixture", Path: "/"})
			fmt.Fprint(w, domains)
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprint(w, domains)
			return
		}
		if _, err := r.Cookie("session"); err != nil {
			t.Error("HE cookie missing")
		}
		if r.Method == "GET" {
			fmt.Fprint(w, record)
			return
		}
		_ = r.ParseForm()
		writes++
		switch r.Form.Get("hosted_dns_editrecord") {
		case "Submit":
			if r.Form.Get("Name") != "txt.example.com" || r.Form.Get("Content") != "a,b" || r.Form.Get("TTL") != "300" {
				t.Error("HE record form malformed")
			}
			fmt.Fprint(w, "Successfully added new record"+record)
		case "Update":
			fmt.Fprint(w, "Successfully updated record"+record)
		default:
			fmt.Fprint(w, "Successfully removed record")
		}
	})
	ctx := context.Background()
	page, err := p.ListDomains(ctx, ListOptions{})
	if err != nil || page.Total != 1 {
		t.Fatal(page, err)
	}
	records, err := p.ListRecords(ctx, ListOptions{})
	if err != nil || len(records.Rows) != 1 || records.Rows[0].Value != "a,b" || records.Rows[0].Priority != nil {
		t.Fatal(records, err)
	}
	r := Record{Name: "txt", Type: "TXT", Value: "a,b", TTL: 300, Enabled: true}
	if _, err = p.GetRecord(ctx, "42"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.CreateRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err = p.UpdateRecord(ctx, "42", r); err != nil {
		t.Fatal(err)
	}
	if err = p.DeleteRecord(ctx, "42"); err != nil {
		t.Fatal(err)
	}
	if login != 1 || writes != 3 {
		t.Fatal(login, writes)
	}
	if err = p.SetStatus(ctx, "42", false); !errors.Is(err, ErrCapability) {
		t.Fatal(err)
	}
}

func TestRESTProviderProtocols(t *testing.T) {
	for _, kind := range []string{"dynv6", "dnsla", "spaceship"} {
		t.Run(kind, func(t *testing.T) {
			seen := map[string]int{}
			p := fixtureProvider(t, kind, Config{"token": "fixture", "apiid": "id", "apisecret": "secret", "apikey": "key"}, "z1", "example.com", func(w http.ResponseWriter, r *http.Request) {
				seen[r.Method]++
				if kind == "dynv6" {
					if r.Header.Get("Authorization") != "Bearer fixture" {
						t.Error("dyn auth missing")
					}
					if r.URL.Path == "/zones" {
						fmt.Fprint(w, `[{"id":"z1","name":"example.com"}]`)
						return
					}
					if r.Method == "GET" {
						fmt.Fprint(w, `[{"id":"r1","name":"www","type":"A","data":"192.0.2.1"}]`)
						return
					}
					if r.Method == "DELETE" {
						w.WriteHeader(204)
						return
					}
					var b map[string]any
					_ = json.NewDecoder(r.Body).Decode(&b)
					if b["name"] != "www" || b["data"] != "192.0.2.1" {
						t.Error(b)
					}
					fmt.Fprint(w, `{"id":"r1"}`)
					return
				}
				if kind == "dnsla" {
					if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
						t.Error("DNSLA auth missing")
					}
					data := any(map[string]any{"id": "r1"})
					switch r.URL.Path {
					case "/api/domainList":
						data = map[string]any{"results": []any{map[string]any{"id": "z1", "displayDomain": "example.com"}}, "total": 1}
					case "/api/recordList":
						data = map[string]any{"results": []any{map[string]any{"id": "r1", "host": "www", "type": 1, "data": "192.0.2.1", "ttl": 300, "lineId": "0", "disable": false}}, "total": 1}
					case "/api/availableLine":
						data = []any{map[string]any{"id": 0, "value": "默认"}}
					case "/api/dnsMeasures":
						data = map[string]any{"minTTL": 300}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": data})
					return
				}
				if r.Header.Get("X-API-Key") != "key" {
					t.Error("Spaceship auth missing")
				}
				if r.URL.Path == "/domains" {
					fmt.Fprint(w, `{"items":[{"name":"example.com"}],"total":1}`)
					return
				}
				if r.Method == "GET" {
					fmt.Fprint(w, `{"items":[{"name":"www","type":"A","address":"192.0.2.1","ttl":300},{"name":"www","type":"A","address":"192.0.2.2","ttl":300}],"total":2}`)
					return
				}
				if r.Method == "PUT" {
					var b map[string]any
					_ = json.NewDecoder(r.Body).Decode(&b)
					items := arr(b, "items")
					if b["force"] == true && (len(items) != 2 || str(items[1], "address") != "192.0.2.2") {
						t.Error("Spaceship update lost sibling", b)
					}
				}
				w.WriteHeader(204)
			})
			ctx := context.Background()
			if _, err := p.ListDomains(ctx, ListOptions{}); err != nil {
				t.Fatal(err)
			}
			page, err := p.ListRecords(ctx, ListOptions{})
			if err != nil || len(page.Rows) == 0 {
				t.Fatal(page, err)
			}
			id := page.Rows[0].ID
			r := Record{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 300, Enabled: true}
			if _, err = p.GetRecord(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, err = p.CreateRecord(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err = p.UpdateRecord(ctx, id, r); err != nil {
				t.Fatal(err)
			}
			if err = p.DeleteRecord(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, err = p.Lines(ctx); err != nil {
				t.Fatal(err)
			}
			if kind == "dnsla" {
				if err = p.SetStatus(ctx, id, false); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestFormProviderProtocols(t *testing.T) {
	for _, kind := range []string{"namesilo", "west", "dnsmgr"} {
		t.Run(kind, func(t *testing.T) {
			p := fixtureProvider(t, kind, Config{"username": "user", "apikey": "key", "api_password": "secret", "uid": "1", "key": "secret"}, "1", "example.com", func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				out := map[string]any{}
				if kind == "namesilo" {
					if r.Method != "GET" || r.Form.Get("key") != "key" {
						t.Error("NameSilo auth/method incorrect")
					}
					out = map[string]any{"code": 300, "record_id": "r1"}
					switch r.URL.Path {
					case "/listDomains":
						out["domains"] = []any{map[string]any{"domain": "example.com"}}
						out["pager"] = map[string]any{"total": 1}
					case "/dnsListRecords":
						out["resource_record"] = []any{map[string]any{"record_id": "r1", "host": "www", "type": "A", "value": "192.0.2.1", "ttl": 3600}}
					}
					out = map[string]any{"reply": out}
				} else if kind == "west" {
					if r.Form.Get("token") != md5Hex("usersecret"+r.Form.Get("time")) {
						t.Error("west signature wrong")
					}
					data := map[string]any{"id": "r1"}
					switch r.Form.Get("act") {
					case "getdomains":
						data["items"] = []any{map[string]any{"domain": "example.com"}}
						data["total"] = 1
					case "getdnsrecord":
						data["items"] = []any{map[string]any{"id": "r1", "item": "www", "type": "A", "value": "192.0.2.1", "ttl": 300, "pause": 0}}
						data["total"] = 1
					}
					out = map[string]any{"result": 200, "data": data}
				} else {
					if r.Form.Get("sign") != md5Hex("1"+r.Form.Get("timestamp")+"secret") {
						t.Error("dnsmgr signature wrong")
					}
					out = map[string]any{"code": 0, "recordid": "r1"}
					switch {
					case r.URL.Path == "/api/domain":
						out = map[string]any{"rows": []any{map[string]any{"id": 1, "name": "example.com"}}, "total": 1}
					case strings.Contains(r.URL.Path, "/api/record/data/"):
						out = map[string]any{"rows": []any{map[string]any{"RecordId": "r1", "Name": "www", "Type": "A", "Value": "192.0.2.1", "TTL": 300, "Status": "1"}}, "total": 1}
					case r.URL.Path == "/api/domain/1":
						out["data"] = map[string]any{"recordLine": []any{map[string]any{"id": "default", "name": "默认"}}, "minTTL": 300}
					}
				}
				_ = json.NewEncoder(w).Encode(out)
			})
			ctx := context.Background()
			if _, err := p.ListDomains(ctx, ListOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := p.ListRecords(ctx, ListOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := p.GetRecord(ctx, "r1"); err != nil {
				t.Fatal(err)
			}
			r := Record{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 3600, Enabled: true}
			if _, err := p.CreateRecord(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := p.UpdateRecord(ctx, "r1", r); err != nil {
				t.Fatal(err)
			}
			if err := p.DeleteRecord(ctx, "r1"); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Lines(ctx); err != nil {
				t.Fatal(err)
			}
			if kind != "namesilo" {
				if err := p.SetStatus(ctx, "r1", false); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestBTGoEdgeTechnitiumProtocols(t *testing.T) {
	for _, kind := range []string{"bt", "goedge", "technitium"} {
		t.Run(kind, func(t *testing.T) {
			p := fixtureProvider(t, kind, Config{"AccessKey": "key", "SecretKey": "secret", "AccountID": "1", "accessKeyId": "id", "accessKey": "key", "nsClusterId": "1", "token": "token"}, "1|1", "example.com", func(w http.ResponseWriter, r *http.Request) {
				if kind == "technitium" {
					_ = r.ParseForm()
					if r.Form.Get("token") != "token" {
						t.Error("Technitium token missing")
					}
					response := map[string]any{}
					switch r.URL.Path {
					case "/zones/list":
						response["zones"] = []any{map[string]any{"name": "example.com"}}
					case "/zones/records/get":
						response["records"] = []any{map[string]any{"name": "www.example.com", "type": "A", "ttl": 300, "rData": map[string]any{"ipAddress": "192.0.2.1"}, "disabled": false, "comments": "keep"}}
					case "/zones/records/add":
						if r.Form.Get("domain") != "www.example.com" || r.Form.Get("ipAddress") != "192.0.2.1" {
							t.Error(r.Form)
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "response": response})
					return
				}
				var b map[string]any
				_ = json.NewDecoder(r.Body).Decode(&b)
				if kind == "bt" {
					if r.Header.Get("X-Access-Key") != "key" || r.Header.Get("X-Signature") == "" {
						t.Error("BT signature missing")
					}
					data := any(map[string]any{"record_id": "r1"})
					switch r.URL.Path {
					case "/api/v1/dns/manage/list_domains":
						data = map[string]any{"data": []any{map[string]any{"local_id": 1, "domain_type": 1, "full_domain": "example.com"}}, "total": 1}
					case "/api/v1/dns/record/list":
						data = map[string]any{"data": []any{map[string]any{"record_id": "r1", "record": "www", "type": "A", "value": "192.0.2.1", "TTL": 300, "viewID": 0, "MX": 1, "state": 0}}, "count": 1}
					case "/api/v1/dns/record/get_views":
						data = []any{map[string]any{"viewId": 0, "name": "默认", "free": true}}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": data})
					return
				}
				if !strings.Contains(r.URL.Path, "getAPIAccessToken") && r.Header.Get("X-Edge-Access-Token") != "token" {
					t.Error("GoEdge token missing")
				}
				record := map[string]any{"id": 1, "name": "www", "type": "A", "value": "192.0.2.1", "ttl": 300, "isOn": true, "description": "keep", "nsRoutes": []any{map[string]any{"code": "default"}}}
				data := map[string]any{}
				switch r.URL.Path {
				case "/APIAccessTokenService/getAPIAccessToken":
					data["token"] = "token"
				case "/NSDomainService/countAllNSDomains":
					data["count"] = 1
				case "/NSDomainService/listNSDomains":
					data["nsDomains"] = []any{map[string]any{"id": 1, "name": "example.com"}}
				case "/NSRecordService/listNSRecords":
					data["nsRecords"] = []any{record}
				case "/NSRecordService/findNSRecord":
					data["nsRecord"] = record
				case "/NSRecordService/createNSRecord":
					data["nsRecordId"] = 1
				case "/NSRouteService/findAllNSRoutes":
					data["nsRoutes"] = []any{map[string]any{"code": "telecom", "name": "电信"}}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": data})
			})
			if kind != "bt" {
				switch x := p.(type) {
				case *goEdge:
					x.zoneID = "1"
				case *technitium:
					x.zoneID = "example.com"
				}
			}
			ctx := context.Background()
			if _, err := p.ListDomains(ctx, ListOptions{}); err != nil {
				t.Fatal(err)
			}
			page, err := p.ListRecords(ctx, ListOptions{})
			if err != nil || len(page.Rows) != 1 {
				t.Fatal(page, err)
			}
			id := page.Rows[0].ID
			r := Record{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 300, Enabled: true}
			if _, err = p.GetRecord(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, err = p.CreateRecord(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err = p.UpdateRecord(ctx, id, r); err != nil {
				t.Fatal(err)
			}
			if err = p.SetStatus(ctx, id, false); err != nil {
				t.Fatal(err)
			}
			if err = p.SetRemark(ctx, id, "changed"); err != nil {
				t.Fatal(err)
			}
			if err = p.DeleteRecord(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, err = p.Lines(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
