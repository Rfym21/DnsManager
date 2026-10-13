package dns

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

type heDNS struct {
	*base
	mu       sync.Mutex
	loggedIn bool
}

func newHE(b *base) (Provider, error) {
	client := *b.client
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client.Jar = jar
	b.client = &client
	return &heDNS{base: b}, nil
}
func htmlAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}
func htmlText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style") {
		return ""
	}
	var s strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		s.WriteString(htmlText(c))
	}
	return strings.TrimSpace(s.String())
}
func htmlVisit(n *html.Node, f func(*html.Node)) {
	f(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		htmlVisit(c, f)
	}
}
func heDocument(s string) (*html.Node, error) { return html.Parse(strings.NewReader(s)) }
func heLoginPage(s string) bool {
	doc, err := heDocument(s)
	if err != nil {
		return false
	}
	email, pass := false, false
	htmlVisit(doc, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			switch htmlAttr(n, "name") {
			case "email":
				email = true
			case "pass":
				pass = true
			}
		}
	})
	return email && pass && !strings.Contains(s, "hosted_dns_zoneid")
}
func heDomains(s string) []Domain {
	doc, err := heDocument(s)
	if err != nil {
		return nil
	}
	rows := []Domain{}
	seen := map[string]bool{}
	htmlVisit(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		id, name := "", ""
		if n.Data == "input" && strings.Contains(htmlAttr(n, "onclick"), "delete_dom(") {
			id, name = htmlAttr(n, "value"), htmlAttr(n, "name")
		}
		if n.Data == "a" {
			u, err := url.Parse(htmlAttr(n, "href"))
			if err == nil {
				id, name = u.Query().Get("hosted_dns_zoneid"), htmlText(n)
			}
		}
		if _, err := strconv.ParseUint(id, 10, 64); err != nil || name == "" || seen[id] {
			return
		}
		if _, err := CanonicalName(name); err != nil {
			return
		}
		seen[id] = true
		rows = append(rows, Domain{ID: id, Name: name})
	})
	return rows
}
func (h *heDNS) records(s string) []Record {
	doc, err := heDocument(s)
	if err != nil {
		return nil
	}
	rows := []Record{}
	htmlVisit(doc, func(n *html.Node) {
		if n.Type != html.ElementNode || n.Data != "tr" || !strings.Contains(" "+htmlAttr(n, "class")+" ", " dns_tr ") {
			return
		}
		cells := []string{}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && c.Data == "td" {
				cells = append(cells, strings.TrimSpace(htmlText(c)))
			}
		}
		if len(cells) < 7 {
			return
		}
		start := 1
		if _, err := strconv.ParseUint(cells[start], 10, 64); err != nil {
			for i, v := range cells {
				if _, err = strconv.ParseUint(v, 10, 64); err == nil && i+5 < len(cells) {
					start = i
					break
				}
			}
		}
		if start+5 >= len(cells) {
			return
		}
		ttl, _ := strconv.Atoi(cells[start+3])
		typ := strings.ToUpper(cells[start+2])
		value := cells[start+5]
		if typ == "TXT" {
			value = strings.Trim(value, "\"")
		}
		var priority *int
		if p, err := strconv.Atoi(cells[start+4]); err == nil {
			priority = &p
		}
		enabled := !strings.Contains(strings.ToLower(htmlAttr(n, "class")), "disabled")
		htmlVisit(n, func(c *html.Node) {
			if htmlAttr(c, "disabled") != "" || strings.Contains(strings.ToLower(htmlAttr(c, "class")), "disabled") {
				enabled = false
			}
		})
		rows = append(rows, Record{ID: cells[start], Name: relative(cells[start+1], h.zoneName), Type: typ, Value: value, Line: "default", TTL: ttl, Priority: priority, Enabled: enabled})
	})
	return rows
}
func (h *heDNS) rawHTML(ctx context.Context, method, path string, q url.Values) (string, error) {
	var raw []byte
	headers := http.Header{"Referer": {h.endpoint + "/"}}
	var query url.Values
	if method == "POST" {
		raw = []byte(q.Encode())
		headers.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		query = q
	}
	data, status, err := h.raw(ctx, method, path, query, raw, headers)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		return "", &RemoteError{Provider: h.kind, Status: status, Message: "HE DNS HTTP request rejected", UnknownResult: status >= 500 && methodWrites(method)}
	}
	return string(data), nil
}
func (h *heDNS) loginLocked(ctx context.Context) (string, error) {
	if h.cfg["username"] == "" || h.cfg["password"] == "" {
		return "", errors.New("HE DNS username and password required")
	}
	if _, err := h.rawHTML(ctx, "GET", "/", nil); err != nil {
		return "", err
	}
	s, err := h.rawHTML(ctx, "POST", "/", url.Values{"email": {h.cfg["username"]}, "pass": {h.cfg["password"]}})
	if err != nil {
		return "", err
	}
	lower := strings.ToLower(s)
	if heLoginPage(s) || strings.Contains(lower, "incorrect") || strings.Contains(lower, "invalid password") || len(heDomains(s)) == 0 && !strings.Contains(s, "hosted_dns_zoneid") {
		return "", errors.New("HE DNS login rejected")
	}
	h.loggedIn = true
	return s, nil
}
func (h *heDNS) request(ctx context.Context, method, path string, q url.Values) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.loggedIn {
		if _, err := h.loginLocked(ctx); err != nil {
			return "", err
		}
	}
	s, err := h.rawHTML(ctx, method, path, q)
	if err != nil {
		return "", err
	}
	if heLoginPage(s) {
		h.loggedIn = false
		if _, err = h.loginLocked(ctx); err != nil {
			return "", err
		}
		s, err = h.rawHTML(ctx, method, path, q)
		if err != nil {
			return "", err
		}
		if heLoginPage(s) {
			h.loggedIn = false
			return "", errors.New("HE DNS session expired after reauthentication")
		}
	}
	return s, nil
}
func (h *heDNS) Validate(ctx context.Context) error {
	_, err := h.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (h *heDNS) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	s, err := h.request(ctx, "GET", "/", nil)
	if err != nil {
		return DomainPage{}, err
	}
	return domainPage(heDomains(s), o), nil
}
func (h *heDNS) zone(ctx context.Context) (string, error) {
	if h.zoneID != "" {
		return h.zoneID, nil
	}
	page, err := h.ListDomains(ctx, ListOptions{Keyword: h.zoneName, PageSize: 1000})
	if err != nil {
		return "", err
	}
	for _, d := range page.Rows {
		if strings.EqualFold(d.Name, h.zoneName) {
			return d.ID, nil
		}
	}
	return "", ErrNotFound
}
func (h *heDNS) all(ctx context.Context) ([]Record, error) {
	zone, err := h.zone(ctx)
	if err != nil {
		return nil, err
	}
	s, err := h.request(ctx, "GET", "/index.cgi", url.Values{"hosted_dns_zoneid": {zone}, "menu": {"edit_zone"}, "hosted_dns_editzone": {""}})
	if err != nil {
		return nil, err
	}
	if !strings.Contains(s, "dns_tr") && !strings.Contains(s, "hosted_dns_zoneid") {
		return nil, errors.New("HE DNS record page could not be parsed")
	}
	return h.records(s), nil
}
func (h *heDNS) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	rows, err := h.all(ctx)
	if err != nil {
		return RecordPage{}, err
	}
	return recordPage(rows, o), nil
}
func (h *heDNS) GetRecord(ctx context.Context, id string) (Record, error) {
	rows, err := h.all(ctx)
	if err != nil {
		return Record{}, err
	}
	for _, r := range rows {
		if r.ID == id {
			return r, nil
		}
	}
	return Record{}, ErrNotFound
}
func (h *heDNS) write(ctx context.Context, id string, r Record) (Record, error) {
	if prepared, err := h.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	if !r.Enabled {
		return Record{}, ErrCapability
	}
	if r.TTL < 300 {
		return Record{}, errors.New("HE DNS minimum TTL is 300 seconds")
	}
	zone, err := h.zone(ctx)
	if err != nil {
		return Record{}, err
	}
	name, err := asciiRecordName(r.Name, h.zoneName)
	if err != nil {
		return Record{}, err
	}
	value := r.Value
	if r.Type == "TXT" {
		value = strings.Trim(value, "\"")
	}
	q := url.Values{"account": {""}, "menu": {"edit_zone"}, "Type": {strings.ToUpper(r.Type)}, "hosted_dns_zoneid": {zone}, "hosted_dns_recordid": {id}, "hosted_dns_editzone": {"1"}, "Priority": {""}, "Name": {name}, "Content": {value}, "TTL": {strconv.Itoa(r.TTL)}}
	if r.Type == "MX" {
		q.Set("Priority", strconv.Itoa(*r.Priority))
	}
	action, message := "Submit", "Successfully added new record"
	if id != "" {
		action, message = "Update", "Successfully updated record"
	}
	q.Set("hosted_dns_editrecord", action)
	s, err := h.request(ctx, "POST", "/index.cgi", q)
	if err != nil {
		return Record{}, err
	}
	if !strings.Contains(strings.ToLower(s), strings.ToLower(message)) {
		return Record{}, &RemoteError{Provider: h.kind, Message: "HE DNS did not confirm record write", UnknownResult: true}
	}
	if id == "" {
		rows := h.records(s)
		if len(rows) == 0 {
			rows, err = h.all(ctx)
			if err != nil {
				return Record{}, acceptedWriteError(h.kind, err)
			}
		}
		for _, record := range rows {
			if strings.EqualFold(record.Name, r.Name) && record.Type == strings.ToUpper(r.Type) && record.Value == r.Value {
				id = record.ID
				break
			}
		}
	}
	if id == "" {
		return Record{}, responseError(h.kind, 200, true, "HE DNS created record ID could not be reconciled")
	}
	r.ID = id
	return r, nil
}
func (h *heDNS) CreateRecord(ctx context.Context, r Record) (Record, error) {
	return h.write(ctx, "", r)
}
func (h *heDNS) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	return h.write(ctx, id, r)
}
func (h *heDNS) DeleteRecord(ctx context.Context, id string) error {
	zone, err := h.zone(ctx)
	if err != nil {
		return err
	}
	s, err := h.request(ctx, "POST", "/index.cgi", url.Values{"menu": {"edit_zone"}, "hosted_dns_zoneid": {zone}, "hosted_dns_recordid": {id}, "hosted_dns_editzone": {"1"}, "hosted_dns_delrecord": {"1"}, "hosted_dns_delconfirm": {"delete"}})
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(s), "successfully removed record") {
		return &RemoteError{Provider: h.kind, Message: "HE DNS did not confirm record deletion", UnknownResult: true}
	}
	return nil
}
func (h *heDNS) MinTTL(context.Context) (int, error) { return 300, nil }

var _ Provider = (*heDNS)(nil)
