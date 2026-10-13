package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

type Cloudflare struct {
	config map[string]string
	client *http.Client
	base   string
}

func NewCloudflare(config map[string]string, client *http.Client) (*Cloudflare, error) {
	if config["api_token"] == "" && config["apikey"] == "" {
		return nil, errors.New("Cloudflare API token is required")
	}
	return &Cloudflare{config: config, client: client, base: "https://api.cloudflare.com/client/v4"}, nil
}

type cfResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
	Info   struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (c *Cloudflare) request(ctx context.Context, method, path string, body any) (cfResponse, error) {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return cfResponse{}, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(data))
	if err != nil {
		return cfResponse{}, err
	}
	token := c.config["api_token"]
	if token == "" {
		token = c.config["apikey"]
	}
	if c.config["email"] != "" && c.config["auth"] == "global" {
		req.Header.Set("X-Auth-Email", c.config["email"])
		req.Header.Set("X-Auth-Key", token)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return cfResponse{}, errors.New("Cloudflare request failed; the remote result may be unknown")
	}
	defer res.Body.Close()
	var output cfResponse
	if err = json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&output); err != nil {
		return output, errors.New("invalid Cloudflare response")
	}
	if !output.Success || res.StatusCode >= 400 {
		if len(output.Errors) > 0 {
			return output, fmt.Errorf("Cloudflare %d: %s", output.Errors[0].Code, output.Errors[0].Message)
		}
		return output, fmt.Errorf("Cloudflare HTTP %d", res.StatusCode)
	}
	return output, nil
}
func (c *Cloudflare) Verify(ctx context.Context) error { _, err := c.Zones(ctx); return err }
func (c *Cloudflare) Zones(ctx context.Context) ([]Zone, error) {
	list := []Zone{}
	for page := 1; page <= 1000; page++ {
		res, err := c.request(ctx, "GET", "/zones?per_page=50&page="+strconv.Itoa(page), nil)
		if err != nil {
			return nil, err
		}
		var raw []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err = json.Unmarshal(res.Result, &raw); err != nil {
			return nil, err
		}
		for _, zone := range raw {
			list = append(list, Zone{ID: zone.ID, Name: zone.Name})
		}
		if page >= res.Info.TotalPages {
			return list, nil
		}
	}
	return nil, errors.New("Cloudflare pagination exceeds safety limit")
}

type cfRecord struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Name     string          `json:"name"`
	Content  string          `json:"content"`
	TTL      int             `json:"ttl"`
	Proxied  bool            `json:"proxied"`
	Priority *int            `json:"priority,omitempty"`
	Comment  string          `json:"comment,omitempty"`
	Modified string          `json:"modified_on"`
	Data     json.RawMessage `json:"data,omitempty"`
}

func normalizeCF(raw cfRecord, zone string) Record {
	return Record{ID: raw.ID, Type: raw.Type, Name: RelativeName(raw.Name, zone), Value: raw.Content, TTL: raw.TTL, Enabled: true, Priority: raw.Priority, Remark: raw.Comment, Proxied: raw.Proxied, Version: raw.Modified, Metadata: raw.Data}
}
func (c *Cloudflare) Records(ctx context.Context, zone Zone) ([]Record, error) {
	list := []Record{}
	for page := 1; page <= 1000; page++ {
		res, err := c.request(ctx, "GET", "/zones/"+url.PathEscape(zone.ID)+"/dns_records?per_page=100&page="+strconv.Itoa(page), nil)
		if err != nil {
			return nil, err
		}
		var raw []cfRecord
		if err = json.Unmarshal(res.Result, &raw); err != nil {
			return nil, err
		}
		for _, record := range raw {
			list = append(list, normalizeCF(record, zone.Name))
		}
		if page >= res.Info.TotalPages {
			return list, nil
		}
	}
	return nil, errors.New("Cloudflare pagination exceeds safety limit")
}
func (c *Cloudflare) write(ctx context.Context, method, path string, zone Zone, record Record) (Record, error) {
	if !record.Enabled {
		return Record{}, errors.New("Cloudflare does not support disabling DNS records")
	}
	if err := ValidateRecord(record, zone.Name); err != nil {
		return Record{}, err
	}
	body := map[string]any{"type": record.Type, "name": AbsoluteName(record.Name, zone.Name), "content": record.Value, "ttl": record.TTL, "comment": record.Remark}
	if record.Type == "A" || record.Type == "AAAA" || record.Type == "CNAME" {
		body["proxied"] = record.Proxied
	}
	if record.Priority != nil {
		body["priority"] = *record.Priority
	}
	if record.Metadata != nil {
		body["data"] = record.Metadata
	}
	res, err := c.request(ctx, method, path, body)
	if err != nil {
		return Record{}, err
	}
	var raw cfRecord
	if err = json.Unmarshal(res.Result, &raw); err != nil {
		return Record{}, err
	}
	return normalizeCF(raw, zone.Name), nil
}
func (c *Cloudflare) Create(ctx context.Context, zone Zone, record Record) (Record, error) {
	return c.write(ctx, "POST", "/zones/"+url.PathEscape(zone.ID)+"/dns_records", zone, record)
}
func (c *Cloudflare) Update(ctx context.Context, zone Zone, record Record) (Record, error) {
	if record.Version != "" {
		res, err := c.request(ctx, "GET", "/zones/"+url.PathEscape(zone.ID)+"/dns_records/"+url.PathEscape(record.ID), nil)
		if err != nil {
			return Record{}, err
		}
		var current cfRecord
		if err = json.Unmarshal(res.Result, &current); err != nil {
			return Record{}, err
		}
		if current.Modified != record.Version {
			return Record{}, errors.New("record changed remotely; refresh before editing")
		}
	}
	return c.write(ctx, "PATCH", "/zones/"+url.PathEscape(zone.ID)+"/dns_records/"+url.PathEscape(record.ID), zone, record)
}
func (c *Cloudflare) Delete(ctx context.Context, zone Zone, id string) error {
	_, err := c.request(ctx, "DELETE", "/zones/"+url.PathEscape(zone.ID)+"/dns_records/"+url.PathEscape(id), nil)
	return err
}
