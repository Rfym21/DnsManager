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

var ErrUnsupported = errors.New("provider operation is not implemented")

type Field struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Secret   bool   `json:"secret"`
	Required bool   `json:"required"`
}
type Descriptor struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Category    string  `json:"category"`
	Implemented bool    `json:"implemented"`
	Fields      []Field `json:"fields"`
}
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Record struct {
	ID       string          `json:"id,omitempty"`
	Type     string          `json:"type"`
	Name     string          `json:"name"`
	Value    string          `json:"value"`
	TTL      int             `json:"ttl"`
	Line     string          `json:"line,omitempty"`
	Enabled  bool            `json:"enabled"`
	Priority *int            `json:"priority,omitempty"`
	Weight   *int            `json:"weight,omitempty"`
	Remark   string          `json:"remark,omitempty"`
	Proxied  bool            `json:"proxied"`
	Version  string          `json:"version,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}
type Provider interface {
	Verify(context.Context) error
	Zones(context.Context) ([]Zone, error)
	Records(context.Context, Zone) ([]Record, error)
	Create(context.Context, Zone, Record) (Record, error)
	Update(context.Context, Zone, Record) (Record, error)
	Delete(context.Context, Zone, string) error
}

func New(kind string, cfg map[string]string) (Provider, error) {
	client := &http.Client{Timeout: 25 * time.Second}
	switch kind {
	case "cloudflare":
		return NewCloudflare(cfg, client)
	}
	return nil, ErrUnsupported
}
func CanonicalName(value string) (string, error) {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", errors.New("invalid domain name")
	}
	ascii = strings.ToLower(ascii)
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid domain label")
		}
	}
	return ascii, nil
}
func AbsoluteName(name, zone string) string {
	if name == "@" || name == "" {
		return zone
	}
	if strings.HasSuffix(name, ".") {
		return strings.TrimSuffix(name, ".")
	}
	if name == zone || strings.HasSuffix(name, "."+zone) {
		return name
	}
	return name + "." + zone
}
func RelativeName(name, zone string) string {
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}
func ValidateRecord(record Record, zone string) error {
	if record.Name == "" || record.Value == "" {
		return errors.New("host and value are required")
	}
	if _, err := CanonicalName(strings.TrimPrefix(AbsoluteName(record.Name, zone), "*.")); err != nil {
		return err
	}
	if record.TTL != 1 && (record.TTL < 60 || record.TTL > 86400) {
		return errors.New("TTL must be auto (1) or 60–86400 seconds")
	}
	switch strings.ToUpper(record.Type) {
	case "A":
		if ip := net.ParseIP(record.Value); ip == nil || ip.To4() == nil {
			return errors.New("A record requires an IPv4 address")
		}
	case "AAAA":
		if ip := net.ParseIP(record.Value); ip == nil || ip.To4() != nil {
			return errors.New("AAAA record requires an IPv6 address")
		}
	case "CNAME", "NS", "MX":
		if _, err := CanonicalName(record.Value); err != nil {
			return errors.New("record value must be a hostname")
		}
		if record.Type == "MX" && (record.Priority == nil || *record.Priority < 0 || *record.Priority > 65535) {
			return errors.New("MX priority is required")
		}
	case "TXT", "CAA", "SRV", "HTTPS", "SVCB", "PTR", "SOA", "NAPTR", "DS", "DNSKEY", "TLSA", "SSHFP", "URI":
	default:
		return fmt.Errorf("unsupported record type %s", record.Type)
	}
	if record.Proxied && record.Type != "A" && record.Type != "AAAA" && record.Type != "CNAME" {
		return errors.New("proxy only supports A, AAAA and CNAME")
	}
	return nil
}
