package deploy

import (
	"fmt"
	"strings"
	"time"
)

// Implemented is the common capability source for the factory and catalog.
func Implemented(kind string) bool {
	switch kind {
	case "local", "ssh", "ftp", "btpanel", "mwpanel", "ratpanel", "acepanel", "nginxproxymanager", "xp", "lucky", "safeline", "opanel", "proxmox", "directadmin", "uusec", "gcore", "cachefly", "axisnow", "rainyun", "baishan", "kuocai", "cdnfly", "lecdn", "goedge", "doge", "cloudpanel", "amh", "kangle", "kangleadmin", "upyun", "synology", "btwaf", "qiniu", "ucloud", "s3storage", "aws", "btwin", "west", "ksyun", "k8s", "huawei", "baidu", "ctyun", "huoshan", "tencent", "unicloud", "fnos", "qzyun", "wangsu", "aliyun":
		return true
	}
	return false
}

func New(kind string, cfg map[string]string, opts Options) (Provider, error) {
	if base := map[string]string{"gcore": "https://api.gcore.com", "cachefly": "https://api.cachefly.com/api/2.5", "axisnow": "https://api.axisnow.io", "rainyun": "https://api.v2.rainyun.com", "baishan": "https://cdn.api.baishan.com", "kuocai": "https://www.kuocaicdn.com", "doge": "https://api.dogecloud.com"}[kind]; base != "" && cfg["url"] == "" {
		copy := map[string]string{}
		for k, v := range cfg {
			copy[k] = v
		}
		copy["url"] = base
		cfg = copy
	}
	switch kind {
	case "aliyun":
		return newAliyun(cfg, opts)
	case "k8s":
		return newK8s(cfg, opts)
	case "local":
		return &localProvider{opts: opts}, nil
	case "ssh":
		return &sshProvider{cfg: cfg, opts: opts}, nil
	case "fnos":
		if opts.Now == nil {
			opts.Now = time.Now
		}
		return &fnosProvider{&sshProvider{cfg: cfg, opts: opts}}, nil
	case "ftp":
		return &ftpProvider{cfg: cfg, opts: opts}, nil
	case "btpanel", "mwpanel", "ratpanel", "acepanel":
		p, err := newHTTP(kind, cfg, opts)
		if err != nil {
			return nil, err
		}
		return &panelProvider{p}, nil
	case "nginxproxymanager":
		p, err := newHTTP(kind, cfg, opts)
		if err != nil {
			return nil, err
		}
		return &npmProvider{httpProvider: p}, nil
	case "xp", "lucky", "safeline", "opanel", "proxmox", "directadmin", "uusec":
		p, err := newHTTP(kind, cfg, opts)
		if err != nil {
			return nil, err
		}
		if kind == "lucky" {
			p.base += strings.TrimRight(cfg["path"], "/")
		}
		switch kind {
		case "proxmox":
			return &proxmoxProvider{p}, nil
		case "directadmin":
			return &directadminProvider{p}, nil
		case "uusec":
			return &uusecProvider{p}, nil
		}
		return &simplePanelProvider{p}, nil
	case "gcore", "cachefly", "axisnow", "rainyun", "baishan", "kuocai", "cdnfly", "lecdn", "goedge", "doge":
		p, err := newHTTP(kind, cfg, opts)
		if err != nil {
			return nil, err
		}
		if kind == "doge" {
			return &dogeProvider{p}, nil
		}
		return &cdnProvider{p}, nil
	case "cloudpanel", "amh", "kangle", "kangleadmin", "upyun", "synology", "btwaf":
		if kind == "upyun" && cfg["url"] == "" {
			copy := map[string]string{}
			for k, v := range cfg {
				copy[k] = v
			}
			copy["url"] = "https://console.upyun.com"
			cfg = copy
		}
		p, err := newHTTP(kind, cfg, opts)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "synology":
			return &synologyProvider{p}, nil
		case "btwaf":
			return &btwafProvider{p}, nil
		}
		return &legacyPanelProvider{p}, nil
	case "qiniu", "ucloud", "s3storage":
		copy := map[string]string{}
		for k, v := range cfg {
			copy[k] = v
		}
		if copy["url"] == "" {
			copy["url"] = map[string]string{"qiniu": "https://api.qiniu.com", "ucloud": "https://api.ucloud.cn", "s3storage": cfg["endpoint"]}[kind]
		}
		p, err := newHTTP(kind, copy, opts)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "qiniu":
			return &qiniuProvider{p}, nil
		case "ucloud":
			return &ucloudDeployProvider{p}, nil
		}
		return &s3Provider{p}, nil
	case "aws":
		copy := map[string]string{}
		for k, v := range cfg {
			copy[k] = v
		}
		if copy["url"] == "" {
			copy["url"] = "https://iam.amazonaws.com"
		}
		p, err := newHTTP(kind, copy, opts)
		if err != nil {
			return nil, err
		}
		p.cfg = cfg
		return &awsProvider{p}, nil
	case "btwin", "west", "ksyun":
		copy := map[string]string{}
		for k, v := range cfg {
			copy[k] = v
		}
		if copy["url"] == "" {
			copy["url"] = map[string]string{"west": "https://api.west.cn/api/v2", "ksyun": "https://cdn.api.ksyun.com"}[kind]
		}
		p, err := newHTTP(kind, copy, opts)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "btwin":
			return &btwinProvider{p}, nil
		case "west":
			return &westProvider{p}, nil
		}
		return &ksyunProvider{p}, nil
	case "huawei", "baidu":
		copy := map[string]string{}
		for k, v := range cfg {
			copy[k] = v
		}
		if copy["url"] == "" {
			copy["url"] = "https://scm.cn-north-4.myhuaweicloud.com"
		}
		p, err := newHTTP(kind, copy, opts)
		if err != nil {
			return nil, err
		}
		p.cfg = cfg
		return &regionalCloudProvider{p}, nil
	case "ctyun":
		copy := map[string]string{}
		for k, v := range cfg {
			copy[k] = v
		}
		if copy["url"] == "" {
			copy["url"] = "https://ctcdn-global.ctapi.ctyun.cn"
		}
		p, err := newHTTP(kind, copy, opts)
		if err != nil {
			return nil, err
		}
		p.cfg = cfg
		return &ctyunProvider{p}, nil
	case "huoshan":
		copy := map[string]string{}
		for k, v := range cfg {
			copy[k] = v
		}
		if copy["url"] == "" {
			copy["url"] = "https://open.volcengineapi.com"
		}
		p, err := newHTTP(kind, copy, opts)
		if err != nil {
			return nil, err
		}
		p.cfg = cfg
		return &volcProvider{p}, nil
	case "tencent":
		copy := map[string]string{}
		for k, v := range cfg {
			copy[k] = v
		}
		if copy["url"] == "" {
			copy["url"] = "https://ssl.tencentcloudapi.com"
		}
		p, err := newHTTP(kind, copy, opts)
		if err != nil {
			return nil, err
		}
		p.cfg = cfg
		return &tencentDeployProvider{p}, nil
	case "unicloud":
		copy := map[string]string{}
		for k, v := range cfg {
			copy[k] = v
		}
		if copy["url"] == "" {
			copy["url"] = "https://account.dcloud.net.cn"
		}
		p, err := newHTTP(kind, copy, opts)
		if err != nil {
			return nil, err
		}
		p.cfg = cfg
		return &unicloudProvider{p, randomSuffix()}, nil
	case "qzyun":
		copy := map[string]string{}
		for k, v := range cfg {
			copy[k] = v
		}
		if copy["url"] == "" {
			copy["url"] = "https://panel.qzyun.cn"
		}
		p, err := newHTTP(kind, copy, opts)
		if err != nil {
			return nil, err
		}
		return &qzyunProvider{p}, nil
	case "wangsu":
		copy := map[string]string{}
		for k, v := range cfg {
			copy[k] = v
		}
		if copy["url"] == "" {
			copy["url"] = "https://open.chinanetcenter.com"
		}
		p, err := newHTTP(kind, copy, opts)
		if err != nil {
			return nil, err
		}
		return &wangsuProvider{p}, nil
	default:
		return nil, fmt.Errorf("deployment provider %q has not been migrated", kind)
	}
}
