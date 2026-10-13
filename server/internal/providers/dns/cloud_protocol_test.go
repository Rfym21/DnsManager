package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCloudRESTProtocols(t *testing.T) {
	for _, kind := range []string{"huawei", "baidu"} {
		t.Run(kind, func(t *testing.T) {
			seen := map[string]int{}
			p := fixtureProvider(t, kind, Config{"AccessKeyId": "fixture-id", "SecretAccessKey": "fixture-secret"}, "z1", "example.com", func(w http.ResponseWriter, r *http.Request) {
				key := r.Method + " " + r.URL.Path
				seen[key]++
				auth := r.Header.Get("Authorization")
				if kind == "huawei" && !strings.HasPrefix(auth, "SDK-HMAC-SHA256 Access=fixture-id,") {
					t.Error("Huawei signature missing")
				}
				if kind == "baidu" && !strings.HasPrefix(auth, "bce-auth-v1/fixture-id/") {
					t.Error("BCE signature missing")
				}
				if strings.Contains(r.URL.Path, "statuses/set") || r.URL.Query().Has("enable") {
					fmt.Fprint(w, `{}`)
					return
				}
				if strings.Contains(r.URL.Path, "/record") {
					if r.Method == "DELETE" {
						w.WriteHeader(204)
						return
					}
					if r.Method == "POST" || r.Method == "PUT" {
						var b map[string]any
						_ = json.NewDecoder(r.Body).Decode(&b)
						if kind == "huawei" {
							vs := stringValues(b, "records")
							if len(vs) != 1 || vs[0] != `"a,b"` || b["name"] != "txt.example.com." {
								t.Errorf("TXT RRSet corrupted %#v", b)
							}
						} else {
							if b["value"] != "a,b" || !r.URL.Query().Has("clientToken") {
								t.Error("BCE record request malformed")
							}
						}
						fmt.Fprint(w, `{"id":"r1"}`)
						return
					}
					if kind == "huawei" {
						if strings.HasSuffix(r.URL.Path, "/r1") {
							fmt.Fprint(w, `{"id":"r1","name":"txt.example.com.","type":"TXT","records":["\"a,b\""],"line":"default_view","ttl":300,"status":"ACTIVE","description":"keep"}`)
						} else {
							if r.URL.Query().Get("offset") != "7" || r.URL.Query().Get("limit") != "7" {
								t.Error("Huawei pagination missing")
							}
							fmt.Fprint(w, `{"recordsets":[{"id":"r1","name":"txt.example.com.","type":"TXT","records":["\"a,b\""],"ttl":300,"status":"ACTIVE"}],"metadata":{"total_count":14}}`)
						}
					} else {
						fmt.Fprint(w, `{"records":[{"id":"r1","rr":"txt","type":"TXT","value":"a,b","line":"default","ttl":300,"status":"running"},{"id":"r2","rr":"other","type":"TXT","value":"c","ttl":300,"status":"running"}]}`)
					}
					return
				}
				if kind == "huawei" {
					fmt.Fprint(w, `{"zones":[{"id":"z1","name":"example.com.","record_num":2}],"metadata":{"total_count":14}}`)
				} else {
					fmt.Fprint(w, `{"zones":[{"id":"z1","name":"example.com"}]}`)
				}
			})
			ctx := context.Background()
			ds, err := p.ListDomains(ctx, ListOptions{Page: 2, PageSize: 7})
			if kind == "baidu" {
				ds, err = p.ListDomains(ctx, ListOptions{})
			}
			if err != nil || len(ds.Rows) != 1 {
				t.Fatal(ds, err)
			}
			page, err := p.ListRecords(ctx, ListOptions{Page: 2, PageSize: 7})
			if err != nil {
				t.Fatal(err)
			}
			if kind == "huawei" && (page.Total != 14 || page.Rows[0].Value != "a,b") {
				t.Fatal(page)
			}
			if kind == "baidu" {
				page, err = p.ListRecords(ctx, ListOptions{Name: "txt", PageSize: 1})
				if err != nil || page.Total != 1 {
					t.Fatal(page, err)
				}
			}
			old, err := p.GetRecord(ctx, "r1")
			if err != nil || old.Name != "txt" || old.Value != "a,b" {
				t.Fatal(old, err)
			}
			rec := Record{Name: "txt", Type: "TXT", Value: "a,b", TTL: 300, Enabled: true}
			created, err := p.CreateRecord(ctx, rec)
			if err != nil || created.ID != "r1" {
				t.Fatal(created, err)
			}
			if _, err = p.UpdateRecord(ctx, "r1", rec); err != nil {
				t.Fatal(err)
			}
			if err = p.DeleteRecord(ctx, "r1"); err != nil {
				t.Fatal(err)
			}
			lines, err := p.Lines(ctx)
			if err != nil || len(lines) == 0 {
				t.Fatal(lines, err)
			}
			if kind == "huawei" && len(lines) != 442 {
				t.Fatal(len(lines))
			}
		})
	}
}

func TestEdgeRPCProtocols(t *testing.T) {
	for _, kind := range []string{"aliyunesa", "tencenteo"} {
		t.Run(kind, func(t *testing.T) {
			seen := map[string]int{}
			p := fixtureProvider(t, kind, Config{"AccessKeyId": "fixture-id", "AccessKeySecret": "fixture-secret", "SecretId": "fixture-id", "SecretKey": "fixture-secret"}, "z1", "example.com", func(w http.ResponseWriter, r *http.Request) {
				var params map[string]any
				action := r.Header.Get("X-TC-Action")
				if kind == "aliyunesa" {
					_ = r.ParseForm()
					action = r.Form.Get("Action")
					signature := r.Form.Get("Signature")
					r.Form.Del("Signature")
					if signature != hmac1("fixture-secret&", r.Method+"&%2F&"+percent(canonicalQuery(r.Form))) {
						t.Error("ESA signature incorrect")
					}
					if r.Form.Get("Version") != "2024-09-10" {
						t.Error("ESA wrong version")
					}
					if action == "CreateRecord" {
						if r.Form.Get("RecordName") != "www.example.com" || r.Form.Get("Type") != "A/AAAA" {
							t.Error("ESA request malformed")
						}
						_ = json.Unmarshal([]byte(r.Form.Get("Data")), &params)
						if params["Value"] != "192.0.2.1" {
							t.Error(params)
						}
					}
				} else {
					_ = json.NewDecoder(r.Body).Decode(&params)
					if r.Header.Get("X-TC-Version") != "2022-09-01" || !strings.Contains(r.Header.Get("Authorization"), "/teo/tc3_request") {
						t.Error("EO signature scope/version incorrect")
					}
				}
				seen[action]++
				out := map[string]any{}
				switch action {
				case "ListSites":
					out = map[string]any{"Sites": []any{map[string]any{"SiteId": "z1", "SiteName": "example.com"}}, "TotalCount": 14}
				case "DescribeZones":
					if params["Offset"] != float64(7) {
						t.Error("EO offset incorrect")
					}
					out = map[string]any{"Zones": []any{map[string]any{"ZoneId": "z1", "ZoneName": "example.com"}}, "TotalCount": 14}
				case "ListRecords", "GetRecord":
					record := map[string]any{"RecordId": "r1", "RecordName": "www.example.com", "RecordType": "A/AAAA", "Data": map[string]any{"Value": "192.0.2.1"}, "Ttl": 300, "Proxied": false}
					if action == "GetRecord" {
						out["RecordModel"] = record
					} else {
						out["Records"] = []any{record}
						out["TotalCount"] = 14
					}
				case "DescribeDnsRecords":
					out = map[string]any{"DnsRecords": []any{map[string]any{"RecordId": "r1", "Name": "www.example.com", "Type": "A", "Content": "192.0.2.1", "Location": "Default", "TTL": 300, "Status": "enable", "Weight": -1}}, "TotalCount": 14}
				case "CreateRecord", "CreateDnsRecord":
					out["RecordId"] = "r1"
				}
				if kind == "tencenteo" {
					out = map[string]any{"Response": out}
				}
				_ = json.NewEncoder(w).Encode(out)
			})
			ctx := context.Background()
			if _, err := p.ListDomains(ctx, ListOptions{Page: 2, PageSize: 7}); err != nil {
				t.Fatal(err)
			}
			page, err := p.ListRecords(ctx, ListOptions{Page: 2, PageSize: 7, Name: "www"})
			if err != nil || page.Total != 14 || page.Rows[0].Type != "A" {
				t.Fatal(page, err)
			}
			old, err := p.GetRecord(ctx, "r1")
			if err != nil || old.Name != "www" {
				t.Fatal(old, err)
			}
			rec := Record{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 300, Enabled: true}
			if _, err = p.CreateRecord(ctx, rec); err != nil {
				t.Fatal(err)
			}
			if _, err = p.UpdateRecord(ctx, "r1", rec); err != nil {
				t.Fatal(err)
			}
			if err = p.DeleteRecord(ctx, "r1"); err != nil {
				t.Fatal(err)
			}
			if kind == "tencenteo" {
				if err = p.SetStatus(ctx, "r1", false); err != nil {
					t.Fatal(err)
				}
				if seen["ModifyDnsRecordsStatus"] != 3 {
					t.Fatal(seen)
				}
			} else if err = p.SetStatus(ctx, "r1", false); !errors.Is(err, ErrCapability) {
				t.Fatal(err)
			}
		})
	}
}

func TestVolcJDProtocols(t *testing.T) {
	for _, kind := range []string{"huoshan", "jdcloud"} {
		t.Run(kind, func(t *testing.T) {
			p := fixtureProvider(t, kind, Config{"AccessKeyId": "fixture-id", "SecretAccessKey": "fixture-secret", "AccessKeySecret": "fixture-secret"}, "1", "example.com", func(w http.ResponseWriter, r *http.Request) {
				var params map[string]any
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &params)
				if kind == "huoshan" {
					if !strings.Contains(r.Header.Get("Authorization"), "/DNS/request") {
						t.Error("Volc scope incorrect")
					}
					out := map[string]any{}
					switch r.URL.Query().Get("Action") {
					case "ListZones":
						out = map[string]any{"Zones": []any{map[string]any{"ZID": 1, "ZoneName": "example.com"}}, "Total": 1}
					case "ListRecords":
						if r.URL.Query().Get("PageNumber") != "2" {
							t.Error("Volc page incorrect")
						}
						out = map[string]any{"Records": []any{map[string]any{"RecordID": "r1", "Host": "www", "Type": "A", "Value": "192.0.2.1", "TTL": 300, "Enable": true}}, "TotalCount": 2}
					case "QueryRecord":
						out = map[string]any{"RecordID": "r1", "Host": "www", "Type": "A", "Value": "192.0.2.1", "TTL": 300, "Enable": true}
					case "CreateRecord":
						if params["Host"] != "www" {
							t.Error(params)
						}
						out["RecordID"] = "r1"
					case "QueryZone":
						out["TradeCode"] = "enterprise_inner"
					case "ListLines":
						out["Lines"] = []any{map[string]any{"Value": "telecom", "Name": "电信", "Level": 2}}
					case "ListCustomLines":
						out["TotalCount"] = 0
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"Result": out})
					return
				}
				if !strings.Contains(r.Header.Get("Authorization"), "JDCLOUD2-HMAC-SHA256 Credential=fixture-id/") {
					t.Error("JD auth incorrect")
				}
				out := map[string]any{}
				switch {
				case strings.HasSuffix(r.URL.Path, "/status"):
				case strings.HasSuffix(r.URL.Path, "/viewTree"):
					out["data"] = []any{map[string]any{"value": 0, "label": "默认", "disabled": false}}
				case strings.Contains(r.URL.Path, "/ResourceRecord") && r.Method == "GET":
					out = map[string]any{"dataList": []any{map[string]any{"id": "r1", "hostRecord": "www", "type": "A", "hostValue": "192.0.2.1", "ttl": 300, "viewValue": []int{0}, "resolvingStatus": 2}}, "totalCount": 1}
				case strings.Contains(r.URL.Path, "/ResourceRecord") && r.Method == "POST":
					if obj(params, "req")["hostRecord"] != "www" {
						t.Error(params)
					}
					out["dataList"] = map[string]any{"id": "r1"}
				case strings.HasSuffix(r.URL.Path, "/domain"):
					out = map[string]any{"dataList": []any{map[string]any{"id": 1, "domainName": "example.com", "packId": 0}}, "totalCount": 1}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"result": out})
			})
			ctx := context.Background()
			if _, err := p.ListDomains(ctx, ListOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := p.ListRecords(ctx, ListOptions{Page: 2, PageSize: 1}); err != nil {
				t.Fatal(err)
			}
			if _, err := p.GetRecord(ctx, "r1"); err != nil {
				t.Fatal(err)
			}
			rec := Record{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 300, Enabled: true}
			if _, err := p.CreateRecord(ctx, rec); err != nil {
				t.Fatal(err)
			}
			if _, err := p.UpdateRecord(ctx, "r1", rec); err != nil {
				t.Fatal(err)
			}
			if err := p.SetStatus(ctx, "r1", false); err != nil {
				t.Fatal(err)
			}
			if err := p.DeleteRecord(ctx, "r1"); err != nil {
				t.Fatal(err)
			}
			ls, err := p.Lines(ctx)
			if err != nil || len(ls) == 0 {
				t.Fatal(ls, err)
			}
			ttl, err := p.MinTTL(ctx)
			if err != nil || ttl < 1 {
				t.Fatal(ttl, err)
			}
		})
	}
}

func TestAliDNSPodCRUDAndCapabilities(t *testing.T) {
	for _, kind := range []string{"aliyun", "dnspod"} {
		t.Run(kind, func(t *testing.T) {
			p := fixtureProvider(t, kind, Config{"AccessKeyId": "id", "AccessKeySecret": "secret", "SecretId": "id", "SecretKey": "secret"}, "1", "example.com", func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				action := r.Form.Get("Action")
				if kind == "dnspod" {
					action = r.Header.Get("X-TC-Action")
				}
				out := map[string]any{}
				switch action {
				case "AddDomainRecord", "CreateRecord":
					out["RecordId"] = 1
				case "DescribeDomainRecordInfo":
					out = map[string]any{"RecordId": 1, "RR": "www", "Type": "A", "Value": "192.0.2.1", "Line": "default", "TTL": 300, "Status": "ENABLE"}
				case "DescribeRecord":
					out["RecordInfo"] = map[string]any{"Id": 1, "SubDomain": "www", "RecordType": "A", "Value": "192.0.2.1", "RecordLineId": "0", "TTL": 300, "Enabled": 1}
				case "DescribeDomainRecords":
					out = map[string]any{"DomainRecords": map[string]any{"Record": []any{map[string]any{"RecordId": 1, "RR": "www", "Type": "A", "Value": "192.0.2.1", "TTL": 300, "Status": "ENABLE"}}}, "TotalCount": 1}
				case "DescribeRecordList":
					out = map[string]any{"RecordList": []any{map[string]any{"RecordId": 1, "Name": "www", "Type": "A", "Value": "192.0.2.1", "TTL": 300, "Status": "ENABLE"}}, "RecordCountInfo": map[string]any{"TotalCount": 1}}
				case "DescribeDomainInfo":
					out = map[string]any{"RecordLines": map[string]any{"RecordLine": []any{map[string]any{"LineCode": "default", "LineDisplayName": "默认"}}}, "MinTtl": 300}
				case "DescribeRecordLineCategoryList":
					out["LineList"] = []any{map[string]any{"LineId": "0", "LineName": "默认", "Useful": true}}
				case "DescribeDomainPurview":
					out["PurviewList"] = []any{map[string]any{"Name": "记录 TTL 最低", "Value": "300"}}
				case "DescribeRecordGroups":
					out["RecordGroups"] = map[string]any{"RecordGroup": []any{map[string]any{"GroupId": 1, "GroupName": "分组"}}}
				case "DescribeRecordGroupList":
					out["GroupList"] = []any{map[string]any{"GroupId": 1, "GroupName": "分组"}}
				case "DescribeRecordLogs":
					out = map[string]any{"RecordLogs": map[string]any{"RecordLog": []any{map[string]any{"ActionTimestamp": 1, "Message": "created"}}}, "TotalCount": 1}
				case "DescribeDomainLogList":
					out = map[string]any{"LogList": []string{"2026-10-12 (192.0.2.1)created Uin: 1"}, "TotalCount": 1}
				case "DescribeDNSSLBSubDomains":
					out = map[string]any{"SlbSubDomains": map[string]any{"SlbSubDomain": []any{map[string]any{"SubDomain": "www.example.com", "Type": "A", "Line": "default", "Open": true}}}, "TotalCount": 1}
				case "DescribeDomainAliasList":
					out["DomainAliasList"] = []any{map[string]any{"Id": 1, "DomainAlias": "alias.example.com"}}
				}
				if kind == "dnspod" {
					out = map[string]any{"Response": out}
				}
				_ = json.NewEncoder(w).Encode(out)
			})
			ctx := context.Background()
			r := Record{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 300, Enabled: true, Remark: "keep"}
			if _, err := p.ListRecords(ctx, ListOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := p.GetRecord(ctx, "1"); err != nil {
				t.Fatal(err)
			}
			if _, err := p.CreateRecord(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := p.UpdateRecord(ctx, "1", r); err != nil {
				t.Fatal(err)
			}
			if err := p.SetStatus(ctx, "1", false); err != nil {
				t.Fatal(err)
			}
			if err := p.SetRemark(ctx, "1", "remark"); err != nil {
				t.Fatal(err)
			}
			if err := p.DeleteRecord(ctx, "1"); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Lines(ctx); err != nil {
				t.Fatal(err)
			}
			if ttl, err := p.MinTTL(ctx); err != nil || ttl != 300 {
				t.Fatal(ttl, err)
			}
			groups := p.(GroupProvider)
			if _, err := groups.Groups(ctx); err != nil {
				t.Fatal(err)
			}
			if err := groups.SetGroup(ctx, []string{"1"}, "1"); err != nil {
				t.Fatal(err)
			}
			logs, total, err := p.(LogProvider).Logs(ctx, ListOptions{})
			if err != nil || total != 1 || logs[0].Message != "created" {
				t.Fatal(logs, total, err)
			}
			if kind == "aliyun" {
				wp := p.(WeightProvider)
				if _, _, err := wp.WeightGroups(ctx, ListOptions{}); err != nil {
					t.Fatal(err)
				}
				if err := wp.SetWeightGroup(ctx, "www", "A", "default", true); err != nil {
					t.Fatal(err)
				}
				if err := wp.SetWeight(ctx, "1", 2); err != nil {
					t.Fatal(err)
				}
			} else {
				ap := p.(AliasProvider)
				if _, err := ap.Aliases(ctx); err != nil {
					t.Fatal(err)
				}
				if err := ap.CreateAlias(ctx, "alias.example.com"); err != nil {
					t.Fatal(err)
				}
				if err := ap.DeleteAlias(ctx, "1"); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
