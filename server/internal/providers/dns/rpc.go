package dns

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type rpcProvider struct{ *base }

func (r *rpcProvider) call(ctx context.Context, action string, params map[string]any) (map[string]any, error) {
	if r.kind == "aliyun" || r.kind == "aliyunesa" {
		return r.aliCall(ctx, action, params)
	}
	return r.tencentCall(ctx, action, params)
}
func rpcMutation(action string) bool {
	for _, prefix := range []string{"Describe", "List", "Get", "Query"} {
		if strings.HasPrefix(action, prefix) {
			return false
		}
	}
	return true
}
func (r *rpcProvider) aliCall(ctx context.Context, action string, params map[string]any) (map[string]any, error) {
	if r.cfg["AccessKeyId"] == "" || r.cfg["AccessKeySecret"] == "" {
		return nil, errors.New("Aliyun access key credentials required")
	}
	version, method := "2015-01-09", "POST"
	if r.kind == "aliyunesa" {
		version = "2024-09-10"
		if strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Get") {
			method = "GET"
		}
	}
	q := url.Values{"Action": {action}, "Format": {"JSON"}, "Version": {version}, "AccessKeyId": {r.cfg["AccessKeyId"]}, "SignatureMethod": {"HMAC-SHA1"}, "Timestamp": {r.now().UTC().Format("2006-01-02T15:04:05Z")}, "SignatureVersion": {"1.0"}, "SignatureNonce": {nonce()}}
	for k, v := range params {
		if v != nil {
			q.Set(k, fmt.Sprint(v))
		}
	}
	canonical := strings.ReplaceAll(q.Encode(), "+", "%20")
	q.Set("Signature", hmac1(r.cfg["AccessKeySecret"]+"&", method+"&%2F&"+percent(canonical)))
	var raw []byte
	var status int
	var err error
	if method == "GET" {
		raw, status, err = r.raw(ctx, method, "/", q, nil, nil)
	} else {
		raw, status, err = r.raw(ctx, method, "/", nil, []byte(q.Encode()), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	}
	if err != nil {
		return nil, classifyProtocolError(err, rpcMutation(action))
	}
	var out map[string]any
	if err = decodeJSON(raw, &out); err != nil || out == nil {
		return nil, responseError(r.kind, status, rpcMutation(action), "invalid Aliyun JSON response")
	}
	if status >= 400 || str(out, "Code") != "" {
		return nil, &RemoteError{Provider: r.kind, Status: status, Code: str(out, "Code"), Message: str(out, "Message"), UnknownResult: status >= 500 && rpcMutation(action)}
	}
	return out, nil
}
func (r *rpcProvider) tencentCall(ctx context.Context, action string, params map[string]any) (map[string]any, error) {
	if r.cfg["SecretId"] == "" || r.cfg["SecretKey"] == "" {
		return nil, errors.New("Tencent Cloud secret credentials required")
	}
	body, _ := json.Marshal(params)
	stamp := r.now().Unix()
	date := r.now().UTC().Format("2006-01-02")
	host, service, version := "dnspod.tencentcloudapi.com", "dnspod", "2021-03-23"
	if r.kind == "tencenteo" {
		host, service, version = "teo.tencentcloudapi.com", "teo", "2022-09-01"
		if r.cfg["site_type"] == "intl" {
			host = "teo.intl.tencentcloudapi.com"
		}
	}
	canonical := "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:" + host + "\n\ncontent-type;host\n" + shaHex(body)
	scope := date + "/" + service + "/tc3_request"
	toSign := "TC3-HMAC-SHA256\n" + strconv.FormatInt(stamp, 10) + "\n" + scope + "\n" + shaHex([]byte(canonical))
	key := hmac256([]byte("TC3"+r.cfg["SecretKey"]), date)
	key = hmac256(key, service)
	key = hmac256(key, "tc3_request")
	signature := hex.EncodeToString(hmac256(key, toSign))
	headers := http.Header{"Content-Type": {"application/json; charset=utf-8"}, "X-TC-Action": {action}, "X-TC-Version": {version}, "X-TC-Timestamp": {strconv.FormatInt(stamp, 10)}, "Authorization": {"TC3-HMAC-SHA256 Credential=" + r.cfg["SecretId"] + "/" + scope + ", SignedHeaders=content-type;host, Signature=" + signature}}
	if token := r.cfg["token"]; token != "" {
		headers.Set("X-TC-Token", token)
	}
	raw, status, err := r.raw(ctx, "POST", "/", nil, body, headers)
	if err != nil {
		return nil, classifyProtocolError(err, rpcMutation(action))
	}
	var envelope map[string]any
	if err = decodeJSON(raw, &envelope); err != nil || envelope == nil {
		return nil, responseError(r.kind, status, rpcMutation(action), "invalid Tencent JSON response")
	}
	out := obj(envelope, "Response")
	if e := obj(out, "Error"); len(e) > 0 {
		return nil, &RemoteError{Provider: r.kind, Status: status, Code: str(e, "Code"), Message: str(e, "Message"), UnknownResult: status >= 500 && rpcMutation(action)}
	}
	if status >= 400 {
		return nil, &RemoteError{Provider: r.kind, Status: status, Message: "HTTP request rejected", UnknownResult: status >= 500 && rpcMutation(action)}
	}
	if _, ok := envelope["Response"].(map[string]any); !ok {
		return nil, responseError(r.kind, status, rpcMutation(action), "missing Tencent response envelope")
	}
	return out, nil
}
func (r *rpcProvider) Validate(ctx context.Context) error {
	_, err := r.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (r *rpcProvider) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	o = normalizedOptions(o)
	rows := []Domain{}
	if r.kind == "aliyun" {
		out, err := r.call(ctx, "DescribeDomains", map[string]any{"PageNumber": o.Page, "PageSize": o.PageSize, "KeyWord": o.Keyword})
		if err != nil {
			return DomainPage{}, err
		}
		for _, d := range arr(obj(out, "Domains"), "Domain") {
			rows = append(rows, Domain{ID: str(d, "DomainId"), Name: str(d, "DomainName"), RecordCount: integer(d, "RecordCount")})
		}
		return DomainPage{Total: integer(out, "TotalCount"), Rows: rows}, nil
	}
	out, err := r.call(ctx, "DescribeDomainList", map[string]any{"Offset": (o.Page - 1) * o.PageSize, "Limit": o.PageSize, "Keyword": o.Keyword})
	if err != nil {
		return DomainPage{}, err
	}
	for _, d := range arr(out, "DomainList") {
		rows = append(rows, Domain{ID: str(d, "DomainId"), Name: str(d, "Name"), RecordCount: integer(d, "RecordCount")})
	}
	return DomainPage{Total: integer(obj(out, "DomainCountInfo"), "DomainTotal"), Rows: rows}, nil
}
func (r *rpcProvider) CreateDomain(ctx context.Context, name string) (Domain, error) {
	name, err := CanonicalName(name)
	if err != nil {
		return Domain{}, err
	}
	if r.kind == "aliyun" {
		d, err := r.call(ctx, "AddDomain", map[string]any{"DomainName": name})
		if err != nil {
			return Domain{}, err
		}
		return Domain{ID: str(d, "DomainId"), Name: str(d, "DomainName")}, nil
	}
	out, err := r.call(ctx, "CreateDomain", map[string]any{"Domain": name})
	if err != nil {
		return Domain{}, err
	}
	d := obj(out, "DomainInfo")
	return Domain{ID: str(d, "Id"), Name: firstString(d, "Domain", "Name")}, nil
}
func rpcType(typ string, toVendor bool) string {
	m := map[string]string{"REDIRECT_URL": "显性URL", "FORWARD_URL": "隐性URL"}
	if toVendor {
		if v := m[typ]; v != "" {
			return v
		}
	} else {
		for k, v := range m {
			if v == typ {
				return k
			}
		}
	}
	return typ
}
func rpcLine(line string, ali bool) string {
	m := map[string]string{"0": "default", "10=1": "unicom", "10=0": "telecom", "10=3": "mobile", "10=2": "edu", "3=0": "oversea", "10=22": "btvn", "80=0": "search", "7=0": "internal"}
	if ali {
		if v, ok := m[line]; ok {
			return v
		}
		if line == "" {
			return "default"
		}
	} else {
		for k, v := range m {
			if v == line {
				return k
			}
		}
		if line == "" {
			return "0"
		}
	}
	return line
}
func (r *rpcProvider) normalize(d map[string]any, info bool) Record {
	if r.kind == "aliyun" {
		return Record{ID: str(d, "RecordId"), Name: str(d, "RR"), Type: str(d, "Type"), Value: str(d, "Value"), Line: str(d, "Line"), TTL: integer(d, "TTL"), Priority: optionalInt(d, "Priority"), Weight: optionalInt(d, "Weight"), Remark: str(d, "Remark"), Enabled: strings.EqualFold(str(d, "Status"), "ENABLE"), Version: str(d, "UpdateTimestamp")}
	}
	if info {
		return Record{ID: str(d, "Id"), Name: str(d, "SubDomain"), Type: rpcType(str(d, "RecordType"), false), Value: str(d, "Value"), Line: str(d, "RecordLineId"), TTL: integer(d, "TTL"), Priority: optionalInt(d, "MX"), Weight: optionalInt(d, "Weight"), Remark: str(d, "Remark"), Enabled: integer(d, "Enabled") == 1, Version: str(d, "UpdatedOn")}
	}
	return Record{ID: str(d, "RecordId"), Name: str(d, "Name"), Type: rpcType(str(d, "Type"), false), Value: str(d, "Value"), Line: str(d, "LineId"), TTL: integer(d, "TTL"), Priority: optionalInt(d, "MX"), Weight: optionalInt(d, "Weight"), Remark: str(d, "Remark"), Enabled: str(d, "Status") == "ENABLE", Version: str(d, "UpdatedOn")}
}
func (r *rpcProvider) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	o = normalizedOptions(o)
	p := map[string]any{}
	action := ""
	sorts := map[string]string{}
	if r.kind == "aliyun" {
		action = "DescribeDomainRecords"
		p = map[string]any{"DomainName": r.zoneName, "PageNumber": o.Page, "PageSize": o.PageSize}
		if o.Name != "" || o.Type != "" || o.Line != "" || o.Value != "" {
			p["SearchMode"] = "ADVANCED"
			p["RRKeyWord"] = o.Name
			p["ValueKeyWord"] = o.Value
			p["Type"] = o.Type
			p["Line"] = o.Line
		} else if o.Keyword != "" {
			p["KeyWord"] = o.Keyword
		}
		if o.Enabled != nil {
			p["Status"] = map[bool]string{true: "Enable", false: "Disable"}[*o.Enabled]
		}
		if o.GroupID != "" {
			p["GroupId"] = o.GroupID
		}
		sorts = map[string]string{"Name": "RR", "Type": "Type", "LineName": "Line", "Value": "Value", "UpdateTime": "UpdateDate"}
		if s := sorts[o.Sort]; s != "" {
			p["OrderBy"] = s
			p["Direction"] = map[bool]string{true: "DESC", false: "ASC"}[o.Desc]
		}
	} else {
		p = map[string]any{"Domain": r.zoneName, "Offset": (o.Page - 1) * o.PageSize, "Limit": o.PageSize}
		if o.Enabled != nil || o.Value != "" || o.GroupID != "" {
			action = "DescribeRecordFilterList"
			if o.Name != "" {
				p["SubDomain"] = o.Name
			}
			if o.Value != "" {
				p["RecordValue"] = o.Value
			}
			if o.Enabled != nil {
				p["RecordStatus"] = []string{map[bool]string{true: "ENABLE", false: "DISABLE"}[*o.Enabled]}
			}
			if o.Type != "" {
				p["RecordType"] = []string{rpcType(o.Type, true)}
			}
			if o.Line != "" {
				p["RecordLine"] = []string{rpcLine(o.Line, false)}
			}
			if o.GroupID != "" {
				id, err := strconv.Atoi(o.GroupID)
				if err != nil {
					return RecordPage{}, errors.New("invalid group ID")
				}
				p["GroupId"] = []int{id}
			}
		} else {
			action = "DescribeRecordList"
			if o.Name != "" {
				p["Subdomain"] = o.Name
			}
			if o.Type != "" {
				p["RecordType"] = rpcType(o.Type, true)
			}
			if o.Line != "" {
				p["RecordLineId"] = rpcLine(o.Line, false)
			}
		}
		if o.Keyword != "" {
			p["Keyword"] = o.Keyword
		}
		sorts = map[string]string{"Name": "name", "Type": "type", "LineName": "line", "Value": "value", "UpdateTime": "updated_on"}
		if s := sorts[o.Sort]; s != "" {
			p["SortField"] = s
			p["SortType"] = map[bool]string{true: "DESC", false: "ASC"}[o.Desc]
		}
	}
	out, err := r.call(ctx, action, p)
	if err != nil {
		var remote *RemoteError
		if errors.As(err, &remote) && (remote.Code == "ResourceNotFound.NoDataOfRecord" || remote.Message == "记录列表为空。" || remote.Message == "No records on the list.") {
			return RecordPage{Rows: []Record{}}, nil
		}
		return RecordPage{}, err
	}
	rows := []Record{}
	raw := arr(out, "RecordList")
	total := integer(obj(out, "RecordCountInfo"), "TotalCount")
	if r.kind == "aliyun" {
		raw = arr(obj(out, "DomainRecords"), "Record")
		total = integer(out, "TotalCount")
	}
	for _, d := range raw {
		rows = append(rows, r.normalize(d, false))
	}
	return RecordPage{Total: total, Rows: rows}, nil
}
func (r *rpcProvider) GetRecord(ctx context.Context, id string) (Record, error) {
	if r.kind == "aliyun" {
		d, err := r.call(ctx, "DescribeDomainRecordInfo", map[string]any{"RecordId": id})
		if err != nil {
			return Record{}, err
		}
		return r.normalize(d, true), nil
	}
	recordID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return Record{}, errors.New("invalid DNSPod record ID")
	}
	out, err := r.call(ctx, "DescribeRecord", map[string]any{"Domain": r.zoneName, "RecordId": recordID})
	if err != nil {
		return Record{}, err
	}
	return r.normalize(obj(out, "RecordInfo"), true), nil
}
func (r *rpcProvider) write(ctx context.Context, id string, record Record) (Record, error) {
	if prepared, err := r.prepare(record); err != nil {
		return Record{}, err
	} else {
		record = prepared
	}
	action := ""
	p := map[string]any{}
	if r.kind == "aliyun" {
		action = "AddDomainRecord"
		p = map[string]any{"DomainName": r.zoneName, "RR": record.Name, "Type": record.Type, "Value": record.Value, "Line": rpcLine(record.Line, true), "TTL": record.TTL}
		if id != "" {
			action = "UpdateDomainRecord"
			delete(p, "DomainName")
			p["RecordId"] = id
		}
		if record.Priority != nil {
			p["Priority"] = *record.Priority
		}
	} else {
		action = "CreateRecord"
		p = map[string]any{"Domain": r.zoneName, "SubDomain": record.Name, "RecordType": rpcType(record.Type, true), "Value": record.Value, "RecordLine": record.Line, "RecordLineId": rpcLine(record.Line, false), "TTL": record.TTL}
		if record.Weight != nil {
			p["Weight"] = *record.Weight
		}
		if record.Type == "MX" && record.Priority != nil {
			p["MX"] = *record.Priority
		}
		if id != "" {
			action = "ModifyRecord"
			recordID, err := strconv.ParseInt(id, 10, 64)
			if err != nil {
				return Record{}, errors.New("invalid DNSPod record ID")
			}
			p["RecordId"] = recordID
		}
	}
	if record.Version != "" && id != "" {
		current, err := r.GetRecord(ctx, id)
		if err != nil {
			return Record{}, err
		}
		if current.Version != record.Version {
			return Record{}, ErrConflict
		}
	}
	out, err := r.call(ctx, action, p)
	if err != nil {
		return Record{}, err
	}
	if writtenID := str(out, "RecordId"); writtenID != "" {
		id = writtenID
	}
	if id == "" {
		return Record{}, responseError(r.kind, 200, true, "provider omitted created record ID")
	}
	record.ID = id
	if record.Remark != "" {
		if err = r.SetRemark(ctx, id, record.Remark); err != nil {
			return record, acceptedWriteError(r.kind, err)
		}
	}
	if id != "" && (!record.Enabled || action == "UpdateDomainRecord" || action == "ModifyRecord") {
		if err = r.SetStatus(ctx, id, record.Enabled); err != nil {
			return record, acceptedWriteError(r.kind, err)
		}
	}
	return record, nil
}
func (r *rpcProvider) CreateRecord(ctx context.Context, record Record) (Record, error) {
	return r.write(ctx, "", record)
}
func (r *rpcProvider) UpdateRecord(ctx context.Context, id string, record Record) (Record, error) {
	return r.write(ctx, id, record)
}
func (r *rpcProvider) simple(ctx context.Context, ali, tencent, id string, extras map[string]any) error {
	p := map[string]any{"RecordId": id}
	action := ali
	if r.kind == "dnspod" {
		action = tencent
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return errors.New("invalid DNSPod record ID")
		}
		p["RecordId"] = n
		p["Domain"] = r.zoneName
	}
	for k, v := range extras {
		p[k] = v
	}
	_, err := r.call(ctx, action, p)
	return err
}
func (r *rpcProvider) DeleteRecord(ctx context.Context, id string) error {
	return r.simple(ctx, "DeleteDomainRecord", "DeleteRecord", id, nil)
}
func (r *rpcProvider) SetStatus(ctx context.Context, id string, enabled bool) error {
	status := map[bool]string{true: "Enable", false: "Disable"}[enabled]
	if r.kind == "dnspod" {
		status = strings.ToUpper(status)
	}
	return r.simple(ctx, "SetDomainRecordStatus", "ModifyRecordStatus", id, map[string]any{"Status": status})
}
func (r *rpcProvider) SetRemark(ctx context.Context, id, remark string) error {
	return r.simple(ctx, "UpdateDomainRecordRemark", "ModifyRecordRemark", id, map[string]any{"Remark": remark})
}
func (r *rpcProvider) Lines(ctx context.Context) ([]Line, error) {
	if r.kind == "aliyun" {
		out, err := r.call(ctx, "DescribeDomainInfo", map[string]any{"DomainName": r.zoneName, "NeedDetailAttributes": "true", "Lang": "zh"})
		if err != nil {
			return nil, err
		}
		rows := []Line{}
		for _, l := range arr(obj(out, "RecordLines"), "RecordLine") {
			rows = append(rows, Line{ID: str(l, "LineCode"), Name: str(l, "LineDisplayName"), Parent: str(l, "FatherCode")})
		}
		return rows, nil
	}
	out, err := r.call(ctx, "DescribeRecordLineCategoryList", map[string]any{"Domain": r.zoneName})
	if err == nil {
		rows := []Line{}
		var visit func([]map[string]any, string)
		visit = func(ls []map[string]any, parent string) {
			for _, l := range ls {
				if !boolean(l, "Useful") {
					continue
				}
				id := str(l, "LineId")
				if id == "" {
					id = "N." + str(l, "LineName")
				}
				rows = append(rows, Line{ID: id, Name: str(l, "LineName"), Parent: parent})
				visit(arr(l, "SubGroup"), id)
			}
		}
		visit(arr(out, "LineList"), "")
		return rows, nil
	}
	out, err = r.call(ctx, "DescribeRecordLineList", map[string]any{"Domain": r.zoneName, "DomainGrade": ""})
	if err != nil {
		return nil, err
	}
	rows := []Line{}
	for _, l := range append(arr(out, "LineList"), arr(out, "LineGroupList")...) {
		rows = append(rows, Line{ID: str(l, "LineId"), Name: str(l, "Name")})
	}
	return rows, nil
}
func (r *rpcProvider) MinTTL(ctx context.Context) (int, error) {
	if r.kind == "aliyun" {
		out, err := r.call(ctx, "DescribeDomainInfo", map[string]any{"DomainName": r.zoneName, "NeedDetailAttributes": "true", "Lang": "zh"})
		if err != nil {
			return 0, err
		}
		return integer(out, "MinTtl"), nil
	}
	out, err := r.call(ctx, "DescribeDomainPurview", map[string]any{"Domain": r.zoneName})
	if err != nil {
		return 0, err
	}
	for _, v := range arr(out, "PurviewList") {
		if str(v, "Name") == "记录 TTL 最低" || str(v, "Name") == "Min TTL value" {
			return integer(v, "Value"), nil
		}
	}
	return 0, errors.New("provider did not return minimum TTL")
}
func (r *rpcProvider) Groups(ctx context.Context) ([]Group, error) {
	action := "DescribeRecordGroups"
	p := map[string]any{"DomainName": r.zoneName, "PageSize": 100, "Lang": "zh"}
	if r.kind == "dnspod" {
		action = "DescribeRecordGroupList"
		p = map[string]any{"Domain": r.zoneName}
	}
	out, err := r.call(ctx, action, p)
	if err != nil {
		return nil, err
	}
	raw := arr(out, "GroupList")
	if r.kind == "aliyun" {
		raw = arr(obj(out, "RecordGroups"), "RecordGroup")
	}
	rows := []Group{}
	for _, g := range raw {
		rows = append(rows, Group{ID: firstString(g, "GroupId", "Id"), Name: firstString(g, "GroupName", "Name")})
	}
	return rows, nil
}
func (r *rpcProvider) SetGroup(ctx context.Context, ids []string, groupID string) error {
	if r.kind == "aliyun" {
		encoded, _ := json.Marshal(ids)
		_, err := r.call(ctx, "ChangeRecordGroup", map[string]any{"DomainName": r.zoneName, "RecordIdList": string(encoded), "GroupId": groupID})
		return err
	}
	id, err := strconv.Atoi(groupID)
	if err != nil {
		return err
	}
	_, err = r.call(ctx, "ModifyRecordToGroup", map[string]any{"Domain": r.zoneName, "GroupId": id, "RecordId": strings.Join(ids, "|")})
	return err
}
func (r *rpcProvider) Aliases(ctx context.Context) ([]Alias, error) {
	if r.kind != "dnspod" {
		return nil, ErrCapability
	}
	out, err := r.call(ctx, "DescribeDomainAliasList", map[string]any{"Domain": r.zoneName})
	if err != nil {
		return nil, err
	}
	rows := []Alias{}
	for _, a := range arr(out, "DomainAliasList") {
		rows = append(rows, Alias{ID: firstString(a, "Id", "DomainAliasId"), Name: firstString(a, "DomainAlias", "Name")})
	}
	return rows, nil
}
func (r *rpcProvider) CreateAlias(ctx context.Context, name string) error {
	if r.kind != "dnspod" {
		return ErrCapability
	}
	name, err := CanonicalName(name)
	if err != nil {
		return err
	}
	_, err = r.call(ctx, "CreateDomainAlias", map[string]any{"Domain": r.zoneName, "DomainAlias": name})
	return err
}
func (r *rpcProvider) DeleteAlias(ctx context.Context, id string) error {
	if r.kind != "dnspod" {
		return ErrCapability
	}
	n, err := strconv.Atoi(id)
	if err != nil {
		return err
	}
	_, err = r.call(ctx, "DeleteDomainAlias", map[string]any{"Domain": r.zoneName, "DomainAliasId": n})
	return err
}
func (r *rpcProvider) WeightGroups(ctx context.Context, o ListOptions) ([]WeightGroup, int, error) {
	if r.kind != "aliyun" {
		return nil, 0, ErrCapability
	}
	o = normalizedOptions(o)
	out, err := r.call(ctx, "DescribeDNSSLBSubDomains", map[string]any{"DomainName": r.zoneName, "PageNumber": o.Page, "PageSize": o.PageSize, "Rr": o.Name})
	if err != nil {
		return nil, 0, err
	}
	rows := []WeightGroup{}
	for _, g := range arr(obj(out, "SlbSubDomains"), "SlbSubDomain") {
		rows = append(rows, WeightGroup{Name: relative(str(g, "SubDomain"), r.zoneName), Type: str(g, "Type"), Line: str(g, "Line"), Enabled: boolean(g, "Open"), Metadata: jsonRaw(g)})
	}
	return rows, integer(out, "TotalCount"), nil
}
func (r *rpcProvider) SetWeightGroup(ctx context.Context, name, typ, line string, enabled bool) error {
	if r.kind != "aliyun" {
		return ErrCapability
	}
	_, err := r.call(ctx, "SetDNSSLBStatus", map[string]any{"DomainName": r.zoneName, "SubDomain": name, "Type": typ, "Line": line, "Open": strconv.FormatBool(enabled)})
	return err
}
func (r *rpcProvider) SetWeight(ctx context.Context, id string, weight int) error {
	if r.kind != "aliyun" {
		return ErrCapability
	}
	if weight < 0 || weight > 100 {
		return errors.New("weight must be 0–100")
	}
	_, err := r.call(ctx, "UpdateDNSSLBWeight", map[string]any{"RecordId": id, "Weight": weight})
	return err
}

var _ Provider = (*rpcProvider)(nil)

func (r *rpcProvider) Logs(ctx context.Context, o ListOptions) ([]Log, int, error) {
	o = normalizedOptions(o)
	p := map[string]any{"DomainName": r.zoneName, "PageNumber": o.Page, "PageSize": o.PageSize, "KeyWord": o.Keyword, "StartDate": o.StartDate, "endDate": o.EndDate, "Lang": "zh"}
	action := "DescribeRecordLogs"
	if r.kind == "dnspod" {
		action = "DescribeDomainLogList"
		p = map[string]any{"Domain": r.zoneName, "Offset": (o.Page - 1) * o.PageSize, "Limit": o.PageSize}
	}
	out, err := r.call(ctx, action, p)
	if err != nil {
		return nil, 0, err
	}
	rows := []Log{}
	if r.kind == "aliyun" {
		for _, l := range arr(obj(out, "RecordLogs"), "RecordLog") {
			ms, _ := strconv.ParseInt(str(l, "ActionTimestamp"), 10, 64)
			rows = append(rows, Log{Time: time.UnixMilli(ms).UTC().Format(time.RFC3339), Message: str(l, "Message")})
		}
	} else {
		a, _ := out["LogList"].([]any)
		for _, item := range a {
			line, ok := item.(string)
			if !ok {
				continue
			}
			log := Log{Message: line}
			before, after, ok := strings.Cut(line, "(")
			if ok {
				ip, msg, closed := strings.Cut(after, ")")
				if closed {
					log.Time = strings.TrimSpace(before)
					log.IP = ip
					log.Message = strings.TrimSpace(strings.SplitN(msg, " Uin:", 2)[0])
				}
			}
			rows = append(rows, log)
		}
	}
	return rows, integer(out, "TotalCount"), nil
}
