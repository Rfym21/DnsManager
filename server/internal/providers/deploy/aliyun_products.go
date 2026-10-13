package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func aliyunJSON(value any) string { raw, _ := json.Marshal(value); return string(raw) }
func aliyunCertID(id, region string) string {
	if region == "ap-southeast-1" {
		return id + "-ap-southeast-1"
	}
	return id + "-cn-hangzhou"
}
func (p *aliyunProvider) esaDeploy(ctx context.Context, id, name, region string, cfg map[string]string, domains []string, info Info) (Info, error) {
	if err := aliyunRequire(cfg, "esa_sitename"); err != nil {
		return info, err
	}
	host := "esa.cn-hangzhou.aliyuncs.com"
	if region == "ap-southeast-1" {
		host = "esa.ap-southeast-1.aliyuncs.com"
	}
	call := func(action string, body map[string]string) (map[string]any, error) {
		return p.rpc(ctx, host, "2024-09-10", http.MethodPost, action, body)
	}
	sites, err := call("ListSites", map[string]string{"SiteName": cfg["esa_sitename"], "SiteSearchType": "exact"})
	if err != nil {
		return info, err
	}
	var siteID string
	for _, raw := range anyList(sites["Sites"]) {
		site := obj(raw)
		if text(site["SiteName"]) == cfg["esa_sitename"] || len(anyList(sites["Sites"])) == 1 {
			siteID = text(site["SiteId"])
			break
		}
	}
	n, err := strconv.ParseInt(siteID, 10, 64)
	if err != nil || n <= 0 {
		return info, errors.New("Aliyun ESA exact site was not found")
	}
	if cfg["product"] == "esa_saas" {
		targets := aliyunTargets(cfg["esa_saas_sitename"], nil)
		return batch(ctx, targets, info, func(domain string) error {
			listed, e := call("ListCustomHostnames", map[string]string{"Hostname": domain, "SiteId": siteID, "NameMatchType": "exact"})
			if e != nil {
				return e
			}
			matches := []map[string]any{}
			for _, raw := range anyList(listed["Hostnames"]) {
				item := obj(raw)
				if strings.EqualFold(text(item["Hostname"]), domain) && text(item["SiteId"]) == siteID {
					matches = append(matches, item)
				}
			}
			if len(matches) != 1 {
				return fmt.Errorf("ESA hostname %s did not return exactly one matching site", domain)
			}
			hostnameID := text(matches[0]["HostnameId"])
			if n, e := strconv.ParseInt(hostnameID, 10, 64); e != nil || n <= 0 {
				return errors.New("ESA hostname ID is invalid")
			}
			_, e = call("UpdateCustomHostname", map[string]string{"HostnameId": hostnameID, "SslFlag": "on", "CertType": "cas", "CasId": id, "CasRegion": region})
			return e
		})
	}
	listed, err := call("ListCertificates", map[string]string{"SiteId": siteID})
	if err != nil {
		return info, err
	}
	var existing, oldest map[string]any
	for _, raw := range anyList(listed["Result"]) {
		cert := obj(raw)
		if text(cert["Type"]) == "free" {
			continue
		}
		sans := aliyunTargets(text(cert["SAN"]), nil)
		covered := len(sans) > 0
		for _, san := range sans {
			found := false
			for _, domain := range domains {
				if strings.EqualFold(san, domain) {
					found = true
					break
				}
			}
			if !found {
				covered = false
			}
		}
		if covered {
			existing = cert
			break
		}
		if oldest == nil || text(cert["CreateTime"]) < text(oldest["CreateTime"]) {
			oldest = cert
		}
	}
	if existing != nil && text(existing["CasId"]) == id {
		return info, nil
	}
	if existing == nil {
		quota, e := call("ListInstanceQuotasWithUsage", map[string]string{"SiteId": siteID, "QuotaNames": "customHttpCert"})
		if e != nil {
			return info, e
		}
		quotas := anyList(quota["Quotas"])
		if len(quotas) > 0 {
			q := obj(quotas[0])
			usage, _ := strconv.Atoi(text(q["Usage"]))
			limit, _ := strconv.Atoi(text(q["QuotaValue"]))
			if limit > 0 && usage >= limit && oldest != nil {
				_, e = call("DeleteCertificate", map[string]string{"SiteId": siteID, "Id": text(oldest["Id"])})
				if e != nil {
					return info, e
				}
				p.log(ctx, "Removed oldest ESA certificate at quota", map[string]any{"site_id": siteID, "certificate_id": oldest["Id"]})
			}
		}
	}
	params := map[string]string{"SiteId": siteID, "Type": "cas", "CasId": id, "Name": name, "Region": region}
	if existing != nil {
		params["Id"] = text(existing["Id"])
	}
	result, err := call("SetCertificate", params)
	if err != nil {
		return info, err
	}
	if value := text(result["Id"]); value != "" {
		info["esa_certificate_id"] = value
		if err = persist(ctx, p.opts, info); err != nil {
			return info, err
		}
	}
	return info, nil
}
func (p *aliyunProvider) wafDeploy(ctx context.Context, id, region string, cfg map[string]string, domains []string, info Info) (Info, error) {
	product := cfg["product"]
	version := "2021-10-01"
	if product == "waf2" {
		version = "2019-09-10"
	}
	host := "wafopenapi." + region + ".aliyuncs.com"
	call := func(action string, params map[string]string) (map[string]any, error) {
		return p.rpc(ctx, host, version, http.MethodPost, action, params)
	}
	action := "DescribeInstance"
	if product == "waf2" {
		action = "DescribeInstanceInfo"
	}
	instance, err := call(action, map[string]string{"RegionId": region})
	if err != nil {
		return info, err
	}
	instanceID := text(instance["InstanceId"])
	if product == "waf2" {
		instanceID = text(obj(instance["InstanceInfo"])["InstanceId"])
	}
	if instanceID == "" {
		return info, errors.New("Aliyun WAF instance not found")
	}
	if product == "wafres" {
		domains = aliyunTargets(cfg["waf_resource_id"], nil)
	}
	return batch(ctx, domains, info, func(domain string) error {
		if product == "waf2" {
			_, e := call("CreateCertificateByCertificateId", map[string]string{"InstanceId": instanceID, "Domain": domain, "CertificateId": id})
			return e
		}
		certID := aliyunCertID(id, region)
		params := map[string]string{"InstanceId": instanceID, "RegionId": region}
		if product == "wafres" {
			parts := strings.Split(domain, "-")
			if len(parts) < 3 || parts[len(parts)-3] == "" {
				return errors.New("WAF resource instance ID cannot be parsed")
			}
			params["CloudResourceId"] = domain
			listed, e := call("DescribeCloudResourceList", params)
			if e != nil {
				return e
			}
			if len(anyList(listed["CloudResourceList"])) == 0 {
				return errors.New("WAF protected cloud resource not found")
			}
			params["CertId"] = certID
			operation := "ModifyCloudResourceDefaultCert"
			if cfg["deploy_type"] == "1" {
				operation = "CreateCloudResourceExtensionCert"
			}
			if _, e = call(operation, params); e != nil {
				return e
			}
			if cfg["deploy_type"] == "1" {
				p.cleanWAF(ctx, call, instanceID, parts[len(parts)-3], domain, region, certID)
			}
			return nil
		}
		params["Domain"] = domain
		detail, e := call("DescribeDomainDetail", params)
		if e != nil {
			return e
		}
		listen := obj(detail["Listen"])
		redirect := obj(detail["Redirect"])
		if listen == nil || redirect == nil {
			return errors.New("WAF listener/redirect configuration is missing")
		}
		if text(listen["CertId"]) == certID {
			return nil
		}
		listen["CertId"] = certID
		if len(anyList(listen["HttpsPorts"])) == 0 {
			listen["HttpsPorts"] = []int{443}
			listen["TLSVersion"] = "tlsv1.1"
			listen["EnableTLSv3"] = true
			listen["CipherSuite"] = 1
		}
		ports := anyList(redirect["BackendPorts"])
		if len(ports) == 1 && text(obj(ports[0])["Protocol"]) == "http" {
			ports = append(ports, map[string]any{"ListenPort": 443, "Protocol": "https", "BackendPort": obj(ports[0])["BackendPort"]})
			redirect["BackendPorts"] = ports
			redirect["FocusHttpBackend"] = true
		}
		if value, ok := redirect["AllBackends"]; ok {
			redirect["Backends"] = value
		}
		params["Listen"], params["Redirect"] = aliyunJSON(listen), aliyunJSON(redirect)
		_, e = call("ModifyDomain", params)
		return e
	})
}
func (p *aliyunProvider) cleanWAF(ctx context.Context, call func(string, map[string]string) (map[string]any, error), instanceID, resourceID, cloudID, region, currentID string) {
	listed, err := call("DescribeResourceInstanceCerts", map[string]string{"InstanceId": instanceID, "ResourceInstanceId": resourceID, "RegionId": region})
	if err != nil {
		p.log(ctx, "Could not list WAF expired extension certificates", nil)
		return
	}
	for _, raw := range anyList(listed["Certs"]) {
		cert := obj(raw)
		id := text(cert["CertIdentifier"])
		if id == "" || id == currentID {
			continue
		}
		expired := false
		for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
			if date, e := time.Parse(layout, text(cert["AfterDate"])); e == nil {
				expired = date.Before(p.opts.Now())
				break
			}
		}
		if !expired {
			continue
		}
		_, e := call("DeleteCloudResourceExtensionCert", map[string]string{"InstanceId": instanceID, "CloudResourceId": cloudID, "CertId": id, "RegionId": region})
		if e != nil {
			p.log(ctx, "Could not remove WAF expired extension certificate", map[string]any{"certificate_id": id})
		}
	}
}
func (p *aliyunProvider) loadBalancer(ctx context.Context, id, name, region, regionID string, cfg map[string]string, info Info) (Info, error) {
	product := cfg["product"]
	host := product + "." + regionID + ".aliyuncs.com"
	version := map[string]string{"clb": "2014-05-15", "alb": "2020-06-16", "nlb": "2022-04-30", "ga": "2019-11-20"}[product]
	if product == "clb" {
		host = "slb." + regionID + ".aliyuncs.com"
	}
	if product == "ga" {
		host = "ga.cn-hangzhou.aliyuncs.com"
	}
	call := func(action string, params map[string]string) (map[string]any, error) {
		return p.rpc(ctx, host, version, http.MethodPost, action, params)
	}
	if product == "clb" {
		if e := aliyunRequire(cfg, "clb_id", "clb_port"); e != nil {
			return info, e
		}
		listed, e := call("DescribeServerCertificates", map[string]string{"RegionId": regionID})
		if e != nil {
			return info, e
		}
		serverID := ""
		for _, raw := range anyList(obj(listed["ServerCertificates"])["ServerCertificate"]) {
			cert := obj(raw)
			if truth(cert["IsAliCloudCertificate"]) && text(cert["AliCloudCertificateId"]) == id {
				serverID = text(cert["ServerCertificateId"])
				break
			}
		}
		if serverID == "" {
			uploaded, e := call("UploadServerCertificate", map[string]string{"RegionId": regionID, "AliCloudCertificateId": id, "AliCloudCertificateName": name, "AliCloudCertificateRegionId": region})
			if e != nil {
				return info, e
			}
			serverID = text(uploaded["ServerCertificateId"])
			if serverID == "" {
				return info, errors.New("CLB server certificate ID is missing")
			}
			info["server_certificate_id"] = serverID
			if e = persist(ctx, p.opts, info); e != nil {
				return info, e
			}
		}
		params := map[string]string{"RegionId": regionID, "LoadBalancerId": cfg["clb_id"], "ListenerPort": cfg["clb_port"]}
		if cfg["deploy_type"] == "1" {
			targets := aliyunTargets(cfg["clb_domain"], nil)
			listed, e := call("DescribeDomainExtensions", params)
			if e != nil {
				return info, e
			}
			return batch(ctx, targets, info, func(domain string) error {
				for _, raw := range anyList(obj(listed["DomainExtensions"])["DomainExtension"]) {
					extension := obj(raw)
					if text(extension["Domain"]) == domain {
						if text(extension["ServerCertificateId"]) == serverID {
							return nil
						}
						_, e := call("SetDomainExtensionAttribute", map[string]string{"RegionId": regionID, "DomainExtensionId": text(extension["DomainExtensionId"]), "ServerCertificateId": serverID})
						return e
					}
				}
				return fmt.Errorf("CLB extension domain %s not found", domain)
			})
		}
		current, e := call("DescribeLoadBalancerHTTPSListenerAttribute", params)
		if e != nil {
			return info, e
		}
		if text(current["ServerCertificateId"]) == serverID {
			return info, nil
		}
		params["ServerCertificateId"] = serverID
		_, e = call("SetLoadBalancerHTTPSListenerAttribute", params)
		return info, e
	}
	certificateID := aliyunCertID(id, region)
	if product == "alb" || product == "nlb" {
		key := product + "_listener_id"
		if e := aliyunRequire(cfg, key); e != nil {
			return info, e
		}
		listenerID := cfg[key]
		if cfg["deploy_type"] == "1" {
			next := ""
			for {
				params := map[string]string{"MaxResults": "50", "ListenerId": listenerID, "CertificateType": "Server"}
				if next != "" {
					params["NextToken"] = next
				}
				listed, e := call("ListListenerCertificates", params)
				if e != nil {
					return info, e
				}
				for _, raw := range anyList(listed["Certificates"]) {
					if text(obj(raw)["CertificateId"]) == certificateID {
						return info, nil
					}
				}
				newToken := text(listed["NextToken"])
				if newToken == "" {
					break
				}
				if newToken == next {
					return info, errors.New("Aliyun listener pagination did not advance")
				}
				next = newToken
			}
			params := map[string]string{"ListenerId": listenerID}
			if product == "alb" {
				params["Certificates.1.CertificateId"] = certificateID
			} else {
				params["AdditionalCertificateIds.1"] = certificateID
			}
			_, e := call("AssociateAdditionalCertificatesWithListener", params)
			return info, e
		}
		params := map[string]string{"ListenerId": listenerID}
		if product == "alb" {
			params["Certificates.1.CertificateId"] = certificateID
		} else {
			params["CertificateIds.1"] = certificateID
		}
		_, e := call("UpdateListenerAttribute", params)
		return info, e
	}
	if e := aliyunRequire(cfg, "ga_id", "ga_listener_id"); e != nil {
		return info, e
	}
	params := map[string]string{"RegionId": "cn-hangzhou", "AcceleratorId": cfg["ga_id"], "ListenerId": cfg["ga_listener_id"]}
	if cfg["deploy_type"] != "1" {
		params["Certificates.1.Id"] = certificateID
		_, e := call("UpdateListener", params)
		return info, e
	}
	listed, e := call("ListListenerCertificates", params)
	if e != nil {
		return info, e
	}
	targets := aliyunTargets(cfg["clb_domain"], nil)
	return batch(ctx, targets, info, func(domain string) error {
		body := map[string]string{}
		for k, v := range params {
			body[k] = v
		}
		for _, raw := range anyList(listed["Certificates"]) {
			cert := obj(raw)
			if text(cert["Domain"]) == domain {
				if text(cert["CertificateId"]) == certificateID {
					return nil
				}
				body["Domain"], body["CertificateId"] = domain, certificateID
				_, e := call("UpdateAdditionalCertificateWithListener", body)
				return e
			}
		}
		body["Certificates.1.Id"], body["Certificates.1.Domain"] = certificateID, domain
		_, e := call("AssociateAdditionalCertificatesWithListener", body)
		return e
	})
}
