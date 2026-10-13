package dns

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type route53 struct{ *base }
type awsSet struct {
	Name       string   `xml:"Name"`
	Type       string   `xml:"Type"`
	TTL        int      `xml:"TTL"`
	Values     []string `xml:"ResourceRecords>ResourceRecord>Value"`
	Identifier string   `xml:"SetIdentifier,omitempty"`
	Alias      *struct {
		Name     string `xml:"DNSName"`
		ZoneID   string `xml:"HostedZoneId"`
		Evaluate bool   `xml:"EvaluateTargetHealth"`
	} `xml:"AliasTarget,omitempty"`
}
type awsList struct {
	XMLName        xml.Name `xml:"ListResourceRecordSetsResponse"`
	Sets           []awsSet `xml:"ResourceRecordSets>ResourceRecordSet"`
	Truncated      bool     `xml:"IsTruncated"`
	NextName       string   `xml:"NextRecordName"`
	NextType       string   `xml:"NextRecordType"`
	NextIdentifier string   `xml:"NextRecordIdentifier"`
}

func (a *route53) request(ctx context.Context, method, path string, q url.Values, body []byte) ([]byte, error) {
	if a.cfg["AccessKeyId"] == "" || a.cfg["SecretAccessKey"] == "" {
		return nil, errors.New("AWS access key credentials required")
	}
	stamp := a.now().UTC().Format("20060102T150405Z")
	date := stamp[:8]
	scope := date + "/us-east-1/route53/aws4_request"
	headers := http.Header{"X-Amz-Date": {stamp}, "Content-Type": {"application/xml"}}
	canonicalHeaders := "host:route53.amazonaws.com\nx-amz-date:" + stamp + "\n"
	signed := "host;x-amz-date"
	if token := a.cfg["session_token"]; token != "" {
		headers.Set("X-Amz-Security-Token", token)
		canonicalHeaders += "x-amz-security-token:" + token + "\n"
		signed += ";x-amz-security-token"
	}
	canonical := method + "\n/2013-04-01" + path + "\n" + strings.ReplaceAll(q.Encode(), "+", "%20") + "\n" + canonicalHeaders + "\n" + signed + "\n" + shaHex(body)
	key := hmac256([]byte("AWS4"+a.cfg["SecretAccessKey"]), date)
	key = hmac256(key, "us-east-1")
	key = hmac256(key, "route53")
	key = hmac256(key, "aws4_request")
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + shaHex([]byte(canonical))
	headers.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+a.cfg["AccessKeyId"]+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(hmac256(key, toSign)))
	raw, status, err := a.raw(ctx, method, path, q, body, headers)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		var e struct {
			Error struct {
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			} `xml:"Error"`
		}
		_ = xml.Unmarshal(raw, &e)
		return nil, &RemoteError{Provider: a.kind, Status: status, Code: e.Error.Code, Message: e.Error.Message, UnknownResult: status >= 500 && methodWrites(method)}
	}
	var root struct{ XMLName xml.Name }
	if err := xml.Unmarshal(raw, &root); err != nil {
		return nil, responseError(a.kind, status, methodWrites(method), "invalid Route53 XML response")
	}
	expected := ""
	switch {
	case strings.Contains(path, "/rrset") && method == "POST":
		expected = "ChangeResourceRecordSetsResponse"
	case strings.Contains(path, "/rrset"):
		expected = "ListResourceRecordSetsResponse"
	case method == "POST" && path == "/hostedzone":
		expected = "CreateHostedZoneResponse"
	case method == "GET" && path == "/hostedzone":
		expected = "ListHostedZonesResponse"
	}
	if expected != "" && root.XMLName.Local != expected {
		return nil, responseError(a.kind, status, methodWrites(method), "unexpected Route53 XML response")
	}
	return raw, nil
}
func (a *route53) Validate(ctx context.Context) error {
	_, err := a.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (a *route53) zoneID() string { return strings.TrimPrefix(a.base.zoneID, "/hostedzone/") }
func (a *route53) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	rows := []Domain{}
	marker := ""
	for page := 0; page < 1000; page++ {
		q := url.Values{"maxitems": {"100"}}
		if marker != "" {
			q.Set("marker", marker)
		}
		raw, err := a.request(ctx, "GET", "/hostedzone", q, nil)
		if err != nil {
			return DomainPage{}, err
		}
		var list struct {
			Zones []struct {
				ID    string `xml:"Id"`
				Name  string `xml:"Name"`
				Count int    `xml:"ResourceRecordSetCount"`
			} `xml:"HostedZones>HostedZone"`
			Truncated bool   `xml:"IsTruncated"`
			Next      string `xml:"NextMarker"`
		}
		if err = xml.Unmarshal(raw, &list); err != nil {
			return DomainPage{}, err
		}
		for _, z := range list.Zones {
			rows = append(rows, Domain{ID: strings.TrimPrefix(z.ID, "/hostedzone/"), Name: strings.TrimSuffix(z.Name, "."), RecordCount: z.Count})
		}
		if !list.Truncated {
			return domainPage(rows, o), nil
		}
		if list.Next == "" || list.Next == marker {
			return DomainPage{}, errors.New("AWS pagination did not advance")
		}
		marker = list.Next
	}
	return DomainPage{}, errors.New("AWS pagination limit exceeded")
}
func (a *route53) CreateDomain(ctx context.Context, name string) (Domain, error) {
	name, err := CanonicalName(name)
	if err != nil {
		return Domain{}, err
	}
	request := struct {
		XMLName xml.Name `xml:"CreateHostedZoneRequest"`
		XMLNS   string   `xml:"xmlns,attr"`
		Name    string   `xml:"Name"`
		Caller  string   `xml:"CallerReference"`
	}{XMLNS: "https://route53.amazonaws.com/doc/2013-04-01/", Name: name, Caller: "dnsmgr-" + nonce()}
	body, err := xml.Marshal(request)
	if err != nil {
		return Domain{}, err
	}
	raw, err := a.request(ctx, "POST", "/hostedzone", nil, body)
	if err != nil {
		return Domain{}, err
	}
	var out struct {
		Zone struct {
			ID   string `xml:"Id"`
			Name string `xml:"Name"`
		} `xml:"HostedZone"`
	}
	if err = xml.Unmarshal(raw, &out); err != nil {
		return Domain{}, err
	}
	return Domain{ID: strings.TrimPrefix(out.Zone.ID, "/hostedzone/"), Name: strings.TrimSuffix(out.Zone.Name, ".")}, nil
}
func (a *route53) sets(ctx context.Context) ([]awsSet, error) {
	rows := []awsSet{}
	q := url.Values{"maxitems": {"300"}}
	last := ""
	for page := 0; page < 1000; page++ {
		raw, err := a.request(ctx, "GET", "/hostedzone/"+pathID(a.zoneID())+"/rrset", q, nil)
		if err != nil {
			return nil, err
		}
		var list awsList
		if err = xml.Unmarshal(raw, &list); err != nil {
			return nil, err
		}
		rows = append(rows, list.Sets...)
		if !list.Truncated {
			return rows, nil
		}
		cursor := list.NextName + "|" + list.NextType + "|" + list.NextIdentifier
		if list.NextName == "" || cursor == last {
			return nil, errors.New("AWS record pagination did not advance")
		}
		last = cursor
		q = url.Values{"maxitems": {"300"}, "name": {list.NextName}, "type": {list.NextType}}
		if list.NextIdentifier != "" {
			q.Set("identifier", list.NextIdentifier)
		}
	}
	return nil, errors.New("AWS record pagination limit exceeded")
}
func (a *route53) normalize(set awsSet, value string) Record {
	parsed, mx := parseContent(set.Type, value)
	name := relative(set.Name, a.zoneName)
	return Record{ID: setID(name, set.Type, value), Name: name, Type: set.Type, Value: parsed, TTL: set.TTL, Line: "default", Enabled: true, Priority: mx, Metadata: jsonRaw(map[string]any{"raw_value": value})}
}
func (a *route53) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	sets, err := a.sets(ctx)
	if err != nil {
		return RecordPage{}, err
	}
	rows := []Record{}
	for _, set := range sets {
		if set.Alias != nil || set.Identifier != "" || set.Type == "SOA" {
			continue
		}
		for _, v := range set.Values {
			rows = append(rows, a.normalize(set, v))
		}
	}
	return recordPage(rows, o), nil
}
func (a *route53) GetRecord(ctx context.Context, id string) (Record, error) {
	name, typ, value, err := splitID(id)
	if err != nil {
		return Record{}, err
	}
	sets, err := a.sets(ctx)
	if err != nil {
		return Record{}, err
	}
	for _, set := range sets {
		if relative(set.Name, a.zoneName) == name && set.Type == typ && set.Identifier == "" && set.Alias == nil {
			for _, v := range set.Values {
				if v == value {
					return a.normalize(set, v), nil
				}
			}
		}
	}
	return Record{}, ErrNotFound
}

type awsChange struct {
	Action string `xml:"Action"`
	Set    awsSet `xml:"ResourceRecordSet"`
}

func (a *route53) change(ctx context.Context, changes []awsChange) error {
	body, err := xml.Marshal(struct {
		XMLName xml.Name    `xml:"ChangeResourceRecordSetsRequest"`
		XMLNS   string      `xml:"xmlns,attr"`
		Changes []awsChange `xml:"ChangeBatch>Changes>Change"`
	}{XMLNS: "https://route53.amazonaws.com/doc/2013-04-01/", Changes: changes})
	if err != nil {
		return err
	}
	_, err = a.request(ctx, "POST", "/hostedzone/"+pathID(a.zoneID())+"/rrset", nil, body)
	return err
}
func findAWSSet(sets []awsSet, name, typ string) (awsSet, bool, error) {
	for _, set := range sets {
		if strings.EqualFold(set.Name, name) && set.Type == typ {
			if set.Alias != nil || set.Identifier != "" {
				return awsSet{}, false, errors.New("alias or routing-policy RRSet requires explicit policy editing")
			}
			return set, true, nil
		}
	}
	return awsSet{Name: name, Type: typ}, false, nil
}
func (a *route53) CreateRecord(ctx context.Context, r Record) (Record, error) {
	return a.mutate(ctx, "", r, false)
}
func (a *route53) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	return a.mutate(ctx, id, r, false)
}
func (a *route53) DeleteRecord(ctx context.Context, id string) error {
	_, err := a.mutate(ctx, id, Record{}, true)
	return err
}
func (a *route53) mutate(ctx context.Context, id string, r Record, remove bool) (Record, error) {
	if !remove {
		if prepared, err := a.prepare(r); err != nil {
			return Record{}, err
		} else {
			r = prepared
		}
		if !r.Enabled {
			return Record{}, ErrCapability
		}
	}
	sets, err := a.sets(ctx)
	if err != nil {
		return Record{}, err
	}
	changes := []awsChange{}
	old := awsSet{}
	oldName, oldType, oldValue := "", "", ""
	oldIndex := -1
	if id != "" {
		oldName, oldType, oldValue, err = splitID(id)
		if err != nil {
			return Record{}, err
		}
		var found bool
		old, found, err = findAWSSet(sets, absolute(oldName, a.zoneName)+".", oldType)
		if err != nil {
			return Record{}, err
		}
		if !found {
			return Record{}, ErrNotFound
		}
		for i, v := range old.Values {
			if v == oldValue {
				oldIndex = i
			}
		}
		if oldIndex < 0 {
			return Record{}, ErrNotFound
		}
	}
	if remove {
		original := old
		old.Values = append(append([]string{}, old.Values[:oldIndex]...), old.Values[oldIndex+1:]...)
		action := "UPSERT"
		if len(old.Values) == 0 {
			old = original
			action = "DELETE"
		}
		return Record{}, a.change(ctx, []awsChange{{Action: action, Set: old}})
	}
	name, err := asciiRecordName(r.Name, a.zoneName)
	if err != nil {
		return Record{}, err
	}
	name += "."
	typ := strings.ToUpper(r.Type)
	if typ == "SPF" {
		typ = "TXT"
	}
	value, err := formatContent(r)
	if err != nil {
		return Record{}, err
	}
	target, _, err := findAWSSet(sets, name, typ)
	if err != nil {
		return Record{}, err
	}
	target.Values = append([]string(nil), target.Values...)
	if id != "" && old.Name == name && old.Type == typ {
		for i, v := range target.Values {
			if i != oldIndex && v == value {
				return Record{}, errors.New("identical record already exists")
			}
		}
		target.Values[oldIndex] = value
	} else {
		for _, v := range target.Values {
			if v == value {
				return Record{}, errors.New("identical record already exists")
			}
		}
		target.Values = append(target.Values, value)
		if id != "" {
			original := old
			old.Values = append(append([]string{}, old.Values[:oldIndex]...), old.Values[oldIndex+1:]...)
			action := "UPSERT"
			if len(old.Values) == 0 {
				action = "DELETE"
				old = original
			}
			changes = append(changes, awsChange{Action: action, Set: old})
		}
	}
	target.TTL = r.TTL
	changes = append(changes, awsChange{Action: "UPSERT", Set: target})
	if err = a.change(ctx, changes); err != nil {
		return Record{}, err
	}
	return a.normalize(target, value), nil
}

var _ Provider = (*route53)(nil)
