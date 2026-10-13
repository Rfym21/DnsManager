package dns

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

//go:embed metadata.json
var metadataFS embed.FS
var descriptors []Descriptor

func init() {
	data, err := metadataFS.ReadFile("metadata.json")
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(data, &descriptors); err != nil {
		panic(err)
	}
}
func Metadata() []Descriptor {
	out := make([]Descriptor, len(descriptors))
	for i, d := range descriptors {
		d.Implemented = implemented(d.ID)
		d.Fields = append([]FormField(nil), d.Fields...)
		for j := range d.Fields {
			d.Fields[j].Options = append([]Option(nil), d.Fields[j].Options...)
			if d.Fields[j].VisibleWhen != nil {
				copyWhen := map[string]string{}
				for k, v := range d.Fields[j].VisibleWhen {
					copyWhen[k] = v
				}
				d.Fields[j].VisibleWhen = copyWhen
			}
		}
		out[i] = d
	}
	return out
}
func Lookup(kind string) (Descriptor, bool) {
	for _, d := range Metadata() {
		if d.ID == kind {
			return d, true
		}
	}
	return Descriptor{}, false
}
func implemented(kind string) bool {
	switch kind {
	case "cloudflare", "aliyun", "dnspod", "powerdns", "aws", "dynv6", "spaceship", "dnsla", "namesilo", "west", "dnsmgr", "goedge", "technitium", "bt", "huawei", "baidu", "aliyunesa", "tencenteo", "huoshan", "jdcloud", "qingcloud", "henet":
		return true
	}
	return false
}
func New(kind string, cfg map[string]string, zoneID, zoneName string) (Provider, error) {
	return NewWithOptions(kind, cfg, zoneID, zoneName, FactoryOptions{})
}
func NewWithOptions(kind string, cfg map[string]string, zoneID, zoneName string, opts FactoryOptions) (Provider, error) {
	if _, ok := Lookup(kind); !ok {
		return nil, fmt.Errorf("unknown DNS provider %q", kind)
	}
	copyCfg := Config{}
	for k, v := range cfg {
		copyCfg[k] = v
	}
	if zoneName != "" {
		ascii, err := CanonicalName(zoneName)
		if err != nil {
			return nil, err
		}
		zoneName = ascii
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 25 * time.Second}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Endpoint == "" {
		opts.Endpoint = endpoints[kind]
	}
	opts.Endpoint = strings.TrimSuffix(opts.Endpoint, "/")
	b := &base{kind: kind, cfg: copyCfg, zoneID: zoneID, zoneName: zoneName, client: opts.Client, endpoint: opts.Endpoint, now: opts.Now}
	return newProvider(b)
}

var endpoints = map[string]string{"bt": "https://dmp.bt.cn", "dynv6": "https://dynv6.com/api/v2", "spaceship": "https://spaceship.dev/api/v1", "dnsla": "https://api.dns.la", "namesilo": "https://www.namesilo.com/api", "west": "https://api.west.cn/api/v2", "cloudflare": "https://api.cloudflare.com/client/v4", "aliyun": "https://alidns.aliyuncs.com", "dnspod": "https://dnspod.tencentcloudapi.com", "aws": "https://route53.amazonaws.com/2013-04-01", "qingcloud": "http://api.routewize.com", "henet": "https://dns.he.net", "huoshan": "https://open.volcengineapi.com", "jdcloud": "https://domainservice.jdcloud-api.com", "huawei": "https://dns.myhuaweicloud.com", "baidu": "https://dns.baidubce.com", "aliyunesa": "https://esa.cn-hangzhou.aliyuncs.com", "tencenteo": "https://teo.tencentcloudapi.com"}

func newProvider(b *base) (Provider, error) {
	switch b.kind {
	case "qingcloud":
		return &qingDNS{base: b}, nil
	case "henet":
		return newHE(b)
	case "huoshan", "jdcloud":
		return &cloudAction{base: b}, nil
	case "huawei", "baidu":
		return &cloudREST{base: b}, nil
	case "aliyunesa", "tencenteo":
		if b.kind == "aliyunesa" && b.cfg["region"] != "" && b.endpoint == endpoints[b.kind] {
			b.endpoint = "https://esa." + b.cfg["region"] + ".aliyuncs.com"
		}
		if b.kind == "tencenteo" && b.cfg["site_type"] == "intl" && b.endpoint == endpoints[b.kind] {
			b.endpoint = "https://teo.intl.tencentcloudapi.com"
		}
		return &edgeDNS{base: b}, nil
	case "bt":
		return &btDNS{base: b}, nil
	case "technitium":
		if b.endpoint == "" {
			b.endpoint = strings.TrimSuffix(b.cfg["url"], "/") + "/api"
		}
		return &technitium{base: b}, nil
	case "goedge":
		if b.endpoint == "" {
			b.endpoint = strings.TrimSuffix(b.cfg["base_url"], "/")
		}
		return &goEdge{base: b}, nil
	case "cloudflare":
		return &cloudflare{base: b}, nil
	case "aliyun", "dnspod":
		return &rpcProvider{base: b}, nil
	case "powerdns":
		return newPowerDNS(b)
	case "aws":
		return &route53{base: b}, nil
	case "dynv6", "spaceship", "dnsla":
		return &restProvider{base: b}, nil
	case "namesilo", "west", "dnsmgr":
		if b.endpoint == "" {
			b.endpoint = strings.TrimSuffix(b.cfg["base_url"], "/")
		}
		return &formProvider{base: b}, nil
	}
	return nil, fmt.Errorf("DNS provider %s has not been migrated yet", b.kind)
}
