// Package deploy implements deployment targets without owning application persistence.
package deploy

import (
	"context"
	"encoding/json"
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
type Condition struct {
	Field  string `json:"field"`
	Equals string `json:"equals"`
	Not    bool   `json:"not,omitempty"`
}
type Descriptor struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Implemented  bool    `json:"implemented"`
	Fields       []Field `json:"fields"`
	TargetFields []Field `json:"target_fields"`
}
type Logger func(context.Context, string, map[string]any)

// Target stores platform task settings separately from secret account configuration.
type Target struct {
	Config  map[string]string `json:"config"`
	Domains []string          `json:"domains"`
}

// Info contains provider resource identities/checkpoints; encrypt any secret payloads.
type Info map[string]any
type Provider interface {
	Validate(context.Context) error
	Deploy(context.Context, string, string, Target, Info) (Info, error)
}
type Options struct {
	HTTPClient *http.Client
	Logger     Logger
	// Local paths are checked against canonical directories supplied by the administrator.
	AllowedDirectories       []string
	RemoteAllowedDirectories []string
	AllowTrustedHooks        bool
	HookTimeout              time.Duration
	// Checkpoint persists newly created IDs before further side effects occur.
	Checkpoint func(context.Context, Info) error
	Now        func() time.Time
}

func cloneInfo(prior Info) Info {
	if prior == nil {
		return Info{}
	}
	raw, _ := json.Marshal(prior)
	var info Info
	_ = json.Unmarshal(raw, &info)
	return info
}

// renewedInfo discards remote identities that refer to an older certificate.
func renewedInfo(prior Info, fingerprint string, identities ...string) Info {
	info := cloneInfo(prior)
	if previous, ok := info["fingerprint"].(string); ok && previous != fingerprint {
		for _, key := range identities {
			delete(info, key)
		}
	}
	info["fingerprint"] = fingerprint
	return info
}
func persist(ctx context.Context, opts Options, info Info) error {
	if opts.Checkpoint == nil {
		return errors.New("deployment checkpoint callback is required for newly created resources")
	}
	return opts.Checkpoint(ctx, cloneInfo(info))
}
