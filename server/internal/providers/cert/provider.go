// Package cert implements certificate issuers independently of HTTP handlers and storage.
package cert

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"time"
)

type Field struct {
	Name        string        `json:"name"`
	Label       string        `json:"label"`
	Type        string        `json:"type"`
	Secret      bool          `json:"secret"`
	Required    bool          `json:"required"`
	Default     string        `json:"default,omitempty"`
	Options     []Option      `json:"options,omitempty"`
	VisibleWhen [][]Condition `json:"visible_when,omitempty"`
}
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// VisibleWhen is an OR of AND groups, containing only field equality comparisons.
type Condition struct {
	Field  string `json:"field"`
	Equals string `json:"equals"`
	Not    bool   `json:"not,omitempty"`
}
type Descriptor struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Registered  bool    `json:"registered"`
	Implemented bool    `json:"implemented"`
	Wildcard    bool    `json:"wildcard"`
	MaxDomains  int     `json:"max_domains"`
	Delegation  bool    `json:"delegation"`
	Fields      []Field `json:"fields"`
}
type Logger func(context.Context, string, map[string]any)
type AccountState struct {
	Email     string         `json:"email"`
	KeyPEM    string         `json:"key_pem"`
	URL       string         `json:"url"`
	Directory string         `json:"directory"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}
type Request struct {
	Domains        []string `json:"domains"`
	KeyType        string   `json:"key_type"`
	KeySize        int      `json:"key_size"`
	PreferredChain string   `json:"preferred_chain,omitempty"`
}
type Challenge struct {
	Domain           string          `json:"domain"`
	Name             string          `json:"name"`
	Type             string          `json:"type"`
	Value            string          `json:"value"`
	URL              string          `json:"url,omitempty"`
	AuthorizationURL string          `json:"authorization_url,omitempty"`
	Presented        bool            `json:"presented"`
	Validated        bool            `json:"validated"`
	Cleaned          bool            `json:"cleaned"`
	Receipt          json.RawMessage `json:"receipt,omitempty"`
}

// Checkpoint contains secrets and must be encrypted by the application before persistence.
type Checkpoint struct {
	Version        int            `json:"version"`
	Provider       string         `json:"provider"`
	Stage          string         `json:"stage"`
	Account        AccountState   `json:"account"`
	OrderURL       string         `json:"order_url,omitempty"`
	FinalizeURL    string         `json:"finalize_url,omitempty"`
	CertificateURL string         `json:"certificate_url,omitempty"`
	PrivateKey     string         `json:"private_key,omitempty"`
	Challenges     []Challenge    `json:"challenges,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}
type SaveCheckpoint func(context.Context, Checkpoint) error
type DNSCallback interface {
	// Present returns an opaque receipt identifying only records created by this job.
	Present(context.Context, Challenge) (json.RawMessage, error)
	Wait(context.Context, Challenge) error
	// Cleanup must remove only the matching value owned by the supplied receipt.
	Cleanup(context.Context, Challenge) error
}
type Result struct {
	Fullchain   string    `json:"fullchain"`
	PrivateKey  string    `json:"private_key"`
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
}
type Provider interface {
	Register(context.Context, AccountState) (AccountState, error)
	Issue(context.Context, Request, *Checkpoint, DNSCallback, SaveCheckpoint) (*Result, error)
	Revoke(context.Context, *Checkpoint, string) error
	Cancel(context.Context, *Checkpoint) error
}
type Options struct {
	HTTPClient   *http.Client
	Logger       Logger
	PollInterval time.Duration
	// Endpoint overrides are for private CA deployments and protocol fixtures.
	Endpoint string
	Now      func() time.Time
	// DNS and persistence callbacks are also used for cloud revocation challenges.
	DNS            DNSCallback
	SaveCheckpoint SaveCheckpoint
}

func ParsePrivateKey(data string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.New("private key must be PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
