// Package dns implements the application's DNS-provider ports without a PHP runtime.
package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

var ErrCapability = errors.New("DNS provider does not offer this capability")
var ErrNotFound = errors.New("DNS record not found")
var ErrConflict = errors.New("DNS record changed; refresh before editing")

type Config = map[string]string

type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}
type FormField struct {
	Name        string            `json:"name"`
	Label       string            `json:"label"`
	Type        string            `json:"type"`
	Required    bool              `json:"required"`
	Secret      bool              `json:"secret"`
	Default     string            `json:"default,omitempty"`
	Placeholder string            `json:"placeholder,omitempty"`
	VisibleWhen map[string]string `json:"visible_when,omitempty"`
	Options     []Option          `json:"options,omitempty"`
}
type Capabilities struct {
	Status           bool `json:"status"`
	Remark           int  `json:"remark"`
	Redirect         bool `json:"redirect"`
	Logs             bool `json:"logs"`
	Weight           bool `json:"weight"`
	ClientPagination bool `json:"client_pagination"`
	CreateDomain     bool `json:"create_domain"`
	Sort             bool `json:"sort"`
	Groups           bool `json:"groups"`
	Aliases          bool `json:"aliases"`
	WeightGroups     bool `json:"weight_groups"`
}
type Descriptor struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Category     string       `json:"category"`
	Implemented  bool         `json:"implemented"`
	Fields       []FormField  `json:"fields"`
	Capabilities Capabilities `json:"capabilities"`
}
type Domain struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	RecordCount int    `json:"record_count,omitempty"`
}
type Record struct {
	ID       string          `json:"id,omitempty"`
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Value    string          `json:"value"`
	Values   []string        `json:"values,omitempty"`
	Line     string          `json:"line,omitempty"`
	TTL      int             `json:"ttl"`
	Priority *int            `json:"priority,omitempty"`
	Weight   *int            `json:"weight,omitempty"`
	Remark   string          `json:"remark,omitempty"`
	Enabled  bool            `json:"enabled"`
	Proxied  bool            `json:"proxied"`
	Version  string          `json:"version,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}
type ListOptions struct {
	Page      int    `json:"page"`
	PageSize  int    `json:"page_size"`
	Keyword   string `json:"keyword,omitempty"`
	Name      string `json:"name,omitempty"`
	Value     string `json:"value,omitempty"`
	Type      string `json:"type,omitempty"`
	Line      string `json:"line,omitempty"`
	Enabled   *bool  `json:"enabled,omitempty"`
	Sort      string `json:"sort,omitempty"`
	Desc      bool   `json:"desc,omitempty"`
	StartDate string `json:"start_date,omitempty"`
	EndDate   string `json:"end_date,omitempty"`
	GroupID   string `json:"group_id,omitempty"`
}
type DomainPage struct {
	Total int      `json:"total"`
	Rows  []Domain `json:"rows"`
}
type RecordPage struct {
	Total int      `json:"total"`
	Rows  []Record `json:"rows"`
}
type Line struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Parent string `json:"parent,omitempty"`
}
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Alias struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Log struct {
	Time    string `json:"time"`
	Message string `json:"message"`
	IP      string `json:"ip,omitempty"`
}
type WeightGroup struct {
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Line     string          `json:"line"`
	Enabled  bool            `json:"enabled"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

type Provider interface {
	Descriptor() Descriptor
	Validate(context.Context) error
	ListDomains(context.Context, ListOptions) (DomainPage, error)
	CreateDomain(context.Context, string) (Domain, error)
	ListRecords(context.Context, ListOptions) (RecordPage, error)
	GetRecord(context.Context, string) (Record, error)
	CreateRecord(context.Context, Record) (Record, error)
	UpdateRecord(context.Context, string, Record) (Record, error)
	DeleteRecord(context.Context, string) error
	SetStatus(context.Context, string, bool) error
	SetRemark(context.Context, string, string) error
	Lines(context.Context) ([]Line, error)
	MinTTL(context.Context) (int, error)
}
type GroupProvider interface {
	Groups(context.Context) ([]Group, error)
	SetGroup(context.Context, []string, string) error
}
type AliasProvider interface {
	Aliases(context.Context) ([]Alias, error)
	CreateAlias(context.Context, string) error
	DeleteAlias(context.Context, string) error
}
type WeightProvider interface {
	WeightGroups(context.Context, ListOptions) ([]WeightGroup, int, error)
	SetWeightGroup(context.Context, string, string, string, bool) error
	SetWeight(context.Context, string, int) error
}
type LogProvider interface {
	Logs(context.Context, ListOptions) ([]Log, int, error)
}

type FactoryOptions struct {
	Client   *http.Client
	Endpoint string
	Now      func() time.Time
}
type base struct {
	kind             string
	cfg              Config
	zoneID, zoneName string
	client           *http.Client
	endpoint         string
	now              func() time.Time
}

func (b *base) Descriptor() Descriptor { d, _ := Lookup(b.kind); return d }
func (b *base) Validate(ctx context.Context) error {
	p, err := newProvider(b)
	if err != nil {
		return err
	}
	_, err = p.ListDomains(ctx, ListOptions{Page: 1, PageSize: 1})
	return err
}

// The registry supplies a concrete provider; base defaults are used only for genuinely absent vendor capabilities.
func (b *base) CreateDomain(context.Context, string) (Domain, error) { return Domain{}, ErrCapability }
func (b *base) SetStatus(context.Context, string, bool) error        { return ErrCapability }
func (b *base) SetRemark(context.Context, string, string) error      { return ErrCapability }
func (b *base) Lines(context.Context) ([]Line, error) {
	return []Line{{ID: "default", Name: "默认"}}, nil
}
func (b *base) MinTTL(context.Context) (int, error) { return 1, nil }
func normalizedOptions(o ListOptions) ListOptions {
	if o.Page < 1 {
		o.Page = 1
	}
	if o.PageSize < 1 {
		o.PageSize = 20
	}
	if o.PageSize > 1000 {
		o.PageSize = 1000
	}
	return o
}
func CanonicalName(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	a, err := idna.Lookup.ToASCII(s)
	if err != nil || a == "" || len(a) > 253 {
		return "", errors.New("invalid domain name")
	}
	for _, label := range strings.Split(a, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid domain label")
		}
	}
	return strings.ToLower(a), nil
}
func absolute(name, zone string) string {
	if name == "@" || name == "" {
		return zone
	}
	name = strings.TrimSuffix(name, ".")
	if strings.EqualFold(name, zone) || strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone)) {
		return name
	}
	return name + "." + zone
}
func relative(name, zone string) string {
	name = strings.TrimSuffix(name, ".")
	if strings.EqualFold(name, zone) {
		return "@"
	}
	if strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone)) {
		return name[:len(name)-len(zone)-1]
	}
	return name
}
func asciiRecordName(name, zone string) (string, error) {
	s := absolute(name, zone)
	labels := strings.Split(s, ".")
	for i, label := range labels {
		if label == "*" {
			continue
		}
		if strings.HasPrefix(label, "_") {
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
					return "", errors.New("invalid DNS label")
				}
			}
			if len(label) > 63 {
				return "", errors.New("DNS label exceeds 63 bytes")
			}
			continue
		}
		a, err := idna.Lookup.ToASCII(label)
		if err != nil {
			return "", err
		}
		if a == "" || len(a) > 63 || strings.HasPrefix(a, "-") || strings.HasSuffix(a, "-") {
			return "", errors.New("invalid DNS label")
		}
		labels[i] = a
	}
	return strings.ToLower(strings.Join(labels, ".")), nil
}
func ValidateRecord(r Record, zone string) error {
	if strings.TrimSpace(r.Name) == "" || r.Value == "" && len(r.Values) == 0 {
		return errors.New("record name and value are required")
	}
	if _, err := asciiRecordName(r.Name, zone); err != nil {
		return errors.New("invalid record name")
	}
	if r.TTL < 1 || r.TTL > 2147483647 {
		return errors.New("TTL must be a positive number of seconds")
	}
	values := r.Values
	if len(values) == 0 {
		values = []string{r.Value}
	}
	for _, value := range values {
		switch strings.ToUpper(r.Type) {
		case "A":
			if ip := net.ParseIP(value); ip == nil || ip.To4() == nil {
				return errors.New("A requires IPv4")
			}
		case "AAAA":
			if ip := net.ParseIP(value); ip == nil || ip.To4() != nil {
				return errors.New("AAAA requires IPv6")
			}
		case "CNAME", "NS", "MX", "PTR":
			if _, err := CanonicalName(value); err != nil {
				return err
			}
		case "TXT", "SPF", "CAA", "SRV", "HTTPS", "SVCB", "SOA", "NAPTR", "DS", "DNSKEY", "TLSA", "SSHFP", "URI", "ALIAS", "ANAME", "DNAME", "APP", "REDIRECT_URL", "FORWARD_URL":
		default:
			return fmt.Errorf("unknown record type %s", r.Type)
		}
	}
	if strings.EqualFold(r.Type, "MX") && (r.Priority == nil || *r.Priority < 0 || *r.Priority > 65535) {
		return errors.New("MX requires priority 0–65535")
	}
	return nil
}

func (b *base) prepare(r Record) (Record, error) {
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	name, err := asciiRecordName(r.Name, b.zoneName)
	if err != nil {
		return r, err
	}
	r.Name = relative(name, b.zoneName)
	if len(r.Values) > 1 && b.kind != "huawei" {
		return r, errors.New("provider requires one value per record")
	}
	if r.Value == "" && len(r.Values) > 0 {
		r.Value = r.Values[0]
	}
	if !r.Enabled && !b.Descriptor().Capabilities.Status {
		return r, ErrCapability
	}
	if r.Type == "CNAME" || r.Type == "NS" || r.Type == "MX" || r.Type == "PTR" {
		r.Value, err = CanonicalName(r.Value)
		if err != nil {
			return r, err
		}
		for i, v := range r.Values {
			r.Values[i], err = CanonicalName(v)
			if err != nil {
				return r, err
			}
		}
	}
	if err = ValidateRecord(r, b.zoneName); err != nil {
		return r, err
	}
	return r, nil
}
