package deploy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type tencentDeployProvider struct{ *httpProvider }

type tencentAPIError struct{ Code, Message string }

func (e *tencentAPIError) Error() string            { return e.Message }
func (e *tencentAPIError) ConfirmedRejection() bool { return true }
func (e *tencentAPIError) SafeToRetry() bool {
	return e.Code == "RequestLimitExceeded" || strings.HasPrefix(e.Code, "RequestLimitExceeded.")
}

func (p *tencentDeployProvider) call(ctx context.Context, service, version, region, action string, body map[string]any) (map[string]any, error) {
	base := "https://" + service + ".tencentcloudapi.com"
	if service == "teo_intl" {
		base = "https://teo.intl.tencentcloudapi.com"
		service = "teo"
	}
	if p.cfg["url"] != "" {
		base = p.base
	}
	raw, e := json.Marshal(body)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	now := p.opts.Now().UTC()
	date := now.Format("2006-01-02")
	timestamp := strconv.FormatInt(now.Unix(), 10)
	scope := date + "/" + service + "/tc3_request"
	canonical := "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:" + req.URL.Host + "\n\ncontent-type;host\n" + sha256hex(raw)
	sign := "TC3-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + sha256hex([]byte(canonical))
	key := hmacSHA256(hmacSHA256(hmacSHA256([]byte("TC3"+p.cfg["SecretKey"]), date), service), "tc3_request")
	req.Header.Set("Authorization", "TC3-HMAC-SHA256 Credential="+p.cfg["SecretId"]+"/"+scope+", SignedHeaders=content-type;host, Signature="+hex.EncodeToString(hmacSHA256(key, sign)))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", version)
	req.Header.Set("X-TC-Timestamp", timestamp)
	if region != "" {
		req.Header.Set("X-TC-Region", region)
	}
	resp, e := p.client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	data, e := readLimited(resp.Body)
	if e != nil {
		return nil, e
	}
	if resp.StatusCode/100 != 2 {
		return nil, rejectedHTTP("Tencent", resp.StatusCode, "provider request failed")
	}
	var response map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&response) != nil {
		return nil, errors.New("invalid Tencent JSON")
	}
	m := obj(response["Response"])
	if m == nil {
		return nil, errors.New("Tencent response envelope missing")
	}
	if err := obj(m["Error"]); len(err) > 0 {
		return nil, &tencentAPIError{Code: text(err["Code"]), Message: safeError(map[string]any{"message": err["Message"]}, p.cfg)}
	}
	return m, nil
}
func (p *tencentDeployProvider) ssl(ctx context.Context, action string, body map[string]any) (map[string]any, error) {
	return p.call(ctx, "ssl", "2019-12-05", "", action, body)
}
func (p *tencentDeployProvider) Validate(ctx context.Context) error {
	if p.cfg["SecretId"] == "" || p.cfg["SecretKey"] == "" {
		return errors.New("Tencent credentials are required")
	}
	_, e := p.ssl(ctx, "DescribeCertificates", map[string]any{})
	return e
}
func pollDeploy(ctx context.Context) error {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (p *tencentDeployProvider) pollRecord(ctx context.Context, id string, info Info) (Info, error) {
	for {
		data, e := p.ssl(ctx, "DescribeHostDeployRecordDetail", map[string]any{"DeployRecordId": id, "Limit": 200})
		if e != nil {
			return info, e
		}
		running, _ := strconv.Atoi(text(data["RunningTotalCount"]))
		pending, _ := strconv.Atoi(text(data["PendingTotalCount"]))
		failed, _ := strconv.Atoi(text(data["FailedTotalCount"]))
		succeeded, _ := strconv.Atoi(text(data["SuccessTotalCount"]))
		if running == 0 && pending == 0 {
			items := []ItemResult{}
			rows := anyList(data["DeployRecordDetailList"])
			total, _ := strconv.Atoi(text(data["TotalCount"]))
			for len(rows) < total {
				page, err := p.ssl(ctx, "DescribeHostDeployRecordDetail", map[string]any{"DeployRecordId": id, "Offset": len(rows), "Limit": 200})
				if err != nil {
					return info, err
				}
				extra := anyList(page["DeployRecordDetailList"])
				if len(extra) == 0 {
					return info, errors.New("Tencent deploy record pagination ended early")
				}
				rows = append(rows, extra...)
			}
			certIDs := []string{}
			seen := map[string]bool{}
			for _, row := range rows {
				m := obj(row)
				status := text(m["Status"])
				ok := status == "1" || status == "success"
				if certID := text(m["CertId"]); certID != "" && !seen[certID] {
					certIDs = append(certIDs, certID)
					seen[certID] = true
				}
				items = append(items, ItemResult{Target: text(m["InstanceId"]), Success: ok, Error: func() string {
					if ok {
						return ""
					}
					return safeError(map[string]any{"msg": m["ErrorMsg"]}, p.cfg)
				}()})
			}
			info["results"] = items
			info["deployment_cert_ids"] = certIDs
			if failed > 0 {
				return info, &PartialError{Succeeded: succeeded, Failed: failed}
			}
			if succeeded == 0 {
				return info, errors.New("Tencent deploy record has no completed successful targets")
			}
			return info, nil
		}
		if e = pollDeploy(ctx); e != nil {
			return info, e
		}
	}
}
func (p *tencentDeployProvider) upload(ctx context.Context, chain, key, name string, info Info) (string, error) {
	v, e := p.ssl(ctx, "UploadCertificate", map[string]any{"CertificatePublicKey": chain, "CertificatePrivateKey": key, "CertificateType": "SVR", "Alias": name, "Repeatable": false, "AllowDownload": true})
	if e != nil {
		return "", e
	}
	id := text(v["CertificateId"])
	if id == "" {
		id = text(v["RepeatCertId"])
	}
	if id == "" {
		return "", errors.New("Tencent upload returned no certificate ID")
	}
	info["cert_id"] = id
	if e = persist(ctx, p.opts, info); e != nil {
		return "", e
	}
	_, e = p.ssl(ctx, "ModifyCertificatesExpiringNotificationSwitch", map[string]any{"CertificateIds": []string{id}, "SwitchStatus": 1})
	return id, e
}
func (p *tencentDeployProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	if target.Config["product"] == "update" || target.Config["product"] == "update_new" {
		return p.update(ctx, chain, key, target, info)
	}
	fingerprint := sha256hex(leaf.Raw)
	id := text(info["cert_id"])
	if text(info["fingerprint"]) != fingerprint {
		id = ""
		delete(info, "cert_id")
		delete(info, "record_id")
	}
	if id == "" {
		info["fingerprint"] = fingerprint
		id, e = p.upload(ctx, chain, key, certName(leaf.Subject.CommonName, leaf.NotBefore.Unix()), info)
		if e != nil {
			return info, e
		}
		info["fingerprint"] = fingerprint
		if e = persist(ctx, p.opts, info); e != nil {
			return info, e
		}
	}
	product := target.Config["product"]
	if product == "upload" {
		return info, nil
	}
	region := target.Config["regionid"]
	switch product {
	case "clb":
		resource := target.Config["clb_id"]
		if resource == "" || region == "" {
			return info, errors.New("Tencent CLB resource and region are required")
		}
		body := map[string]any{"LoadBalancerId": resource, "Protocol": "HTTPS"}
		if listener := target.Config["clb_listener_id"]; listener != "" {
			body["ListenerIds"] = []string{listener}
		}
		v, e := p.call(ctx, "clb", "2018-03-17", region, "DescribeListeners", body)
		if e != nil {
			return info, e
		}
		rows := map[string]map[string]any{}
		ids := []string{}
		sni := target.Config["clb_domain"] != ""
		for _, row := range anyList(v["Listeners"]) {
			m := obj(row)
			if truth(m["SniSwitch"]) != sni {
				continue
			}
			listener := text(m["ListenerId"])
			if sni {
				for _, rule := range anyList(m["Rules"]) {
					r := obj(rule)
					if text(r["Domain"]) == target.Config["clb_domain"] {
						ids = append(ids, listener)
						rows[listener] = r
					}
				}
			} else {
				ids = append(ids, listener)
				rows[listener] = m
			}
		}
		return batch(ctx, ids, info, func(listener string) error {
			if text(obj(rows[listener]["Certificate"])["CertId"]) == id {
				return nil
			}
			action := "ModifyListener"
			body := map[string]any{"LoadBalancerId": resource, "ListenerId": listener, "Certificate": map[string]string{"SSLMode": "UNIDIRECTIONAL", "CertId": id}}
			if sni {
				action = "ModifyDomainAttributes"
				body["Domain"] = target.Config["clb_domain"]
			}
			_, e := p.call(ctx, "clb", "2018-03-17", region, action, body)
			return e
		})
	case "scf":
		if region == "" {
			return info, errors.New("Tencent SCF region is required")
		}
		return batch(ctx, splitLines(strings.ReplaceAll(target.Config["domain"], ",", "\n")), info, func(domain string) error {
			v, e := p.call(ctx, "scf", "2018-04-16", region, "GetCustomDomain", map[string]any{"Domain": domain})
			if e != nil {
				return e
			}
			cert := obj(v["CertConfig"])
			if cert == nil {
				cert = map[string]any{}
			}
			cert["CertificateId"] = id
			protocol := text(v["Protocol"])
			if protocol == "HTTP" {
				protocol = "HTTP&HTTPS"
			}
			_, e = p.call(ctx, "scf", "2018-04-16", region, "UpdateCustomDomain", map[string]any{"Domain": domain, "Protocol": protocol, "CertConfig": cert})
			return e
		})
	case "teo":
		if target.Config["site_id"] != "" {
			service := "teo"
			if target.Config["site_type"] == "intl" {
				service = "teo_intl"
			}
			_, e = p.call(ctx, service, "2022-09-01", "", "ModifyHostsCertificate", map[string]any{"ZoneId": target.Config["site_id"], "Hosts": strings.Split(target.Config["domain"], ","), "Mode": "sslcert", "ServerCertInfo": []any{map[string]string{"CertId": id}}})
			return info, e
		}
	}
	if record := text(info["record_id"]); record != "" {
		return p.pollRecord(ctx, record, info)
	}
	instances := []string{}
	switch product {
	case "cos":
		if region == "" || target.Config["cos_bucket"] == "" || target.Config["domain"] == "" {
			return info, errors.New("Tencent COS region, bucket and domain are required")
		}
		instances = append(instances, region+"|"+target.Config["cos_bucket"]+"|"+target.Config["domain"])
	case "tke":
		if region == "" || target.Config["tke_cluster_id"] == "" || target.Config["tke_namespace"] == "" || target.Config["tke_secret"] == "" {
			return info, errors.New("Tencent TKE cluster, namespace, secret and region are required")
		}
		instances = append(instances, target.Config["tke_cluster_id"]+"|"+target.Config["tke_namespace"]+"|"+target.Config["tke_secret"])
	case "lighthouse":
		if region == "" || target.Config["lighthouse_id"] == "" || target.Config["domain"] == "" {
			return info, errors.New("Tencent Lighthouse region, instance and domain are required")
		}
		instances = append(instances, region+"|"+target.Config["lighthouse_id"]+"|"+target.Config["domain"])
	case "ddos":
		if target.Config["lighthouse_id"] == "" || target.Config["domain"] == "" {
			return info, errors.New("Tencent DDOS instance and domain are required")
		}
		instances = append(instances, target.Config["lighthouse_id"]+"|"+target.Config["domain"]+"|443")
	case "cdn", "waf", "teo", "live", "vod", "tse", "apigateway", "tcb", "mqtt", "tdmq":
		instances = splitLines(strings.ReplaceAll(target.Config["domain"], ",", "\n"))
		if product == "cdn" {
			for i := range instances {
				instances[i] += "|on"
			}
		}
		if product == "waf" {
			region = target.Config["region"]
		}
	default:
		return info, errors.New("invalid Tencent deployment product")
	}
	if len(instances) == 0 {
		return info, errors.New("Tencent deployment targets are required")
	}
	body := map[string]any{"CertificateId": id, "InstanceIdList": instances, "ResourceType": product}
	if product == "live" {
		body["Status"] = 1
	}
	v, e := p.call(ctx, "ssl", "2019-12-05", region, "DeployCertificateInstance", body)
	if e != nil {
		return info, e
	}
	record := text(v["DeployRecordId"])
	if record == "" || record == "0" {
		return info, errors.New("Tencent deployment returned no record ID")
	}
	info["record_id"] = record
	if e = persist(ctx, p.opts, info); e != nil {
		return info, e
	}
	return p.pollRecord(ctx, record, info)
}

// verifiedCertificateID compares the actual DER certificate, never a fuzzy domain match.
func (p *tencentDeployProvider) verifiedCertificateID(ctx context.Context, id, fingerprint string) (bool, error) {
	if id == "" {
		return false, nil
	}
	v, err := p.ssl(ctx, "DescribeCertificateDetail", map[string]any{"CertificateId": id})
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode([]byte(text(v["CertificatePublicKey"])))
	if block == nil {
		return false, errors.New("Tencent certificate detail omitted certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, errors.New("Tencent returned invalid certificate PEM")
	}
	return sha256hex(certificate.Raw) == fingerprint, nil
}
func (p *tencentDeployProvider) findUpdatedCertificate(ctx context.Context, info Info, domain, fingerprint string) (string, error) {
	candidates := append([]string{text(info["updated_cert_id"])}, stringList(info["deployment_cert_ids"])...)
	seen := map[string]bool{}
	verify := func(id string) (bool, error) {
		if id == "" || seen[id] {
			return false, nil
		}
		seen[id] = true
		return p.verifiedCertificateID(ctx, id, fingerprint)
	}
	for _, id := range candidates {
		ok, err := verify(id)
		if err != nil {
			return "", err
		}
		if ok {
			return id, nil
		}
	}
	for offset := 0; ; {
		v, err := p.ssl(ctx, "DescribeCertificates", map[string]any{"SearchKey": domain, "CertificateType": "SVR", "Offset": offset, "Limit": 100})
		if err != nil {
			return "", err
		}
		rows := anyList(v["Certificates"])
		for _, raw := range rows {
			id := text(obj(raw)["CertificateId"])
			ok, err := verify(id)
			if err != nil {
				return "", err
			}
			if ok {
				return id, nil
			}
		}
		total, _ := strconv.Atoi(text(v["TotalCount"]))
		offset += len(rows)
		if len(rows) == 0 || offset >= total {
			break
		}
	}
	return "", errors.New("Tencent updated certificate cannot yet be verified; retry without deleting old certificate")
}
func (p *tencentDeployProvider) finishUpdate(ctx context.Context, target Target, info Info, domain, fingerprint string) (Info, error) {
	if record := text(info["update_record_id"]); record != "" && !truth(info["update_complete"]) {
		var err error
		info, err = p.pollRecord(ctx, record, info)
		if err != nil {
			return info, err
		}
	}
	id, err := p.findUpdatedCertificate(ctx, info, domain, fingerprint)
	if err != nil {
		return info, err
	}
	info["updated_cert_id"] = id
	info["update_complete"] = true
	if err = persist(ctx, p.opts, info); err != nil {
		return info, err
	}
	old := text(info["update_old_cert_id"])
	if target.Config["product"] == "update_new" && truth(target.Config["delete_old_cert"]) && old != id && !truth(info["old_cert_deleted"]) {
		_, err = p.ssl(ctx, "DeleteCertificate", map[string]any{"CertificateId": old})
		var apiErr *tencentAPIError
		if err != nil && !(errors.As(err, &apiErr) && strings.HasPrefix(apiErr.Code, "ResourceNotFound")) {
			return info, err
		}
		info["old_cert_deleted"] = true
		if err = persist(ctx, p.opts, info); err != nil {
			return info, err
		}
	}
	return info, nil
}
func (p *tencentDeployProvider) update(ctx context.Context, chain, key string, target Target, info Info) (Info, error) {
	leaf, _, _, err := parsePair(chain, key)
	if err != nil {
		return info, err
	}
	fingerprint := sha256hex(leaf.Raw)
	old := target.Config["cert_id"]
	identity := sha256hex([]byte(target.Config["product"] + "\n" + old))
	same := text(info["update_fingerprint"]) == fingerprint && text(info["update_target_identity"]) == identity
	if same {
		old = text(info["update_old_cert_id"])
	} else {
		if truth(info["update_complete"]) && text(info["updated_cert_id"]) != "" && text(info["update_target_identity"]) == identity {
			old = text(info["updated_cert_id"])
		}
		for _, key := range []string{"update_record_id", "resource_task_id", "update_complete", "old_cert_deleted", "deployment_cert_ids", "results", "cert_id", "updated_cert_id"} {
			delete(info, key)
		}
		info["update_fingerprint"] = fingerprint
		info["fingerprint"] = fingerprint
		info["update_target_identity"] = identity
		info["update_old_cert_id"] = old
	}
	if old == "" {
		return info, errors.New("Tencent old certificate ID is required")
	}
	if text(info["update_record_id"]) != "" || truth(info["update_complete"]) {
		return p.finishUpdate(ctx, target, info, leaf.Subject.CommonName, fingerprint)
	}
	task := text(info["resource_task_id"])
	if task == "" {
		v, e := p.ssl(ctx, "CreateCertificateBindResourceSyncTask", map[string]any{"CertificateIds": []string{old}, "IsCache": 1})
		if e != nil {
			return info, e
		}
		tasks := anyList(v["CertTaskIds"])
		if len(tasks) == 0 {
			return info, errors.New("Tencent resource sync returned no task ID")
		}
		task = text(obj(tasks[0])["TaskId"])
		if task == "" {
			return info, errors.New("Tencent resource sync returned empty task ID")
		}
		info["resource_task_id"] = task
		if e = persist(ctx, p.opts, info); e != nil {
			return info, e
		}
	}
	types := []string{}
	regions := []any{}
	regionTypes := map[string]bool{"clb": true, "tke": true, "apigateway": true, "waf": true, "tcb": true, "tse": true, "cos": true, "mqtt": true, "scf": true, "tdmq": true}
	for {
		v, e := p.ssl(ctx, "DescribeCertificateBindResourceTaskResult", map[string]any{"TaskIds": []string{task}})
		if e != nil {
			return info, e
		}
		rows := anyList(v["SyncTaskBindResourceResult"])
		if len(rows) == 0 {
			return info, errors.New("Tencent resource sync result empty")
		}
		row := obj(rows[0])
		status := text(row["Status"])
		if status == "2" {
			return info, errors.New("Tencent resource sync failed")
		}
		if status == "1" {
			for _, resource := range anyList(row["BindResourceResult"]) {
				m := obj(resource)
				kind := text(m["ResourceType"])
				if target.Config["product"] == "update" && kind != "clb" {
					continue
				}
				list := []string{}
				count := 0
				for _, region := range anyList(m["BindResourceRegionResult"]) {
					r := obj(region)
					n, _ := strconv.Atoi(text(r["TotalCount"]))
					count += n
					if n > 0 && text(r["Region"]) != "" {
						list = append(list, text(r["Region"]))
					}
				}
				if count > 0 {
					types = append(types, kind)
					if regionTypes[kind] && len(list) > 0 {
						regions = append(regions, map[string]any{"ResourceType": kind, "Regions": list})
					}
				}
			}
			break
		}
		if status != "0" {
			return info, errors.New("Tencent resource sync returned unknown state")
		}
		if e = pollDeploy(ctx); e != nil {
			return info, e
		}
	}
	if len(types) == 0 {
		if target.Config["product"] == "update" {
			return info, errors.New("Tencent certificate has no CLB resources to update")
		}
		id := text(info["cert_id"])
		if id == "" {
			id, err = p.upload(ctx, chain, key, certName(leaf.Subject.CommonName, leaf.NotBefore.Unix()), info)
			if err != nil {
				return info, err
			}
		}
		info["updated_cert_id"] = id
		if err = persist(ctx, p.opts, info); err != nil {
			return info, err
		}
		return p.finishUpdate(ctx, target, info, leaf.Subject.CommonName, fingerprint)
	}
	action := "UploadUpdateCertificateInstance"
	if target.Config["product"] == "update_new" {
		action = "UpdateCertificateInstance"
	}
	body := map[string]any{"OldCertificateId": old, "CertificatePublicKey": chain, "CertificatePrivateKey": key, "ResourceTypes": types}
	if len(regions) > 0 {
		body["ResourceTypesRegions"] = regions
	}
	for {
		v, e := p.ssl(ctx, action, body)
		if e != nil {
			return info, e
		}
		record := text(v["DeployRecordId"])
		if record != "" && record != "0" {
			info["update_record_id"] = record
			if id := text(v["CertificateId"]); id != "" {
				info["updated_cert_id"] = id
			}
			if e = persist(ctx, p.opts, info); e != nil {
				return info, e
			}
			return p.finishUpdate(ctx, target, info, leaf.Subject.CommonName, fingerprint)
		}
		if e = pollDeploy(ctx); e != nil {
			return info, e
		}
	}
}
