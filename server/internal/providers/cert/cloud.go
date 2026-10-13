package cert

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

func (p *cloudProvider) Register(ctx context.Context, state AccountState) (AccountState, error) {
	var action string
	params := map[string]any{}
	var required []string
	switch p.kind {
	case "tencent":
		required = []string{"SecretId", "SecretKey", "email"}
		action = "DescribeCertificates"
	case "aliyun":
		required = []string{"AccessKeyId", "AccessKeySecret"}
		action = "ListInstances"
	case "ucloud":
		required = []string{"PublicKey", "PrivateKey", "username", "phone", "email"}
		action = "GetCertificateList"
		params["Mode"] = "free"
	case "huoshan":
		required = []string{"AccessKeyId", "SecretAccessKey"}
		action = "CertificateGetInstance"
		params = map[string]any{"limit": 1, "offset": 0}
	}
	for _, field := range required {
		if p.cfg[field] == "" {
			return state, fmt.Errorf("%s is required", field)
		}
	}
	_, err := p.call(ctx, http.MethodGet, action, params, nil)
	return state, err
}
func (p *cloudProvider) Issue(ctx context.Context, request Request, cp *Checkpoint, dns DNSCallback, save SaveCheckpoint) (*Result, error) {
	if cp == nil || dns == nil || save == nil {
		return nil, errors.New("checkpoint, persistence and DNS callbacks are required")
	}
	if cp.Provider != "" && cp.Provider != p.kind {
		return nil, errors.New("checkpoint belongs to another provider")
	}
	domains, err := validateDomains(request.Domains, 1, false)
	if err != nil {
		return nil, err
	}
	request, err = cloudKeyRequest(p.kind, request)
	if err != nil {
		return nil, err
	}
	if err = checkpointRequest(cp, request, domains); err != nil {
		return nil, err
	}
	cp.Provider = p.kind
	cp.Version = 1
	if cp.Metadata == nil {
		cp.Metadata = map[string]any{}
	}
	if _, err = p.Register(ctx, cp.Account); err != nil {
		return nil, err
	}
	if cp.Stage == "" {
		cp.Stage = "creating_order"
		if err = save(ctx, *cp); err != nil {
			return nil, err
		}
	}
	if err = p.create(ctx, request, domains[0], cp, save); err != nil {
		return nil, err
	}
	if len(cp.Challenges) == 0 {
		if err = p.challenges(ctx, domains[0], cp); err != nil {
			return nil, err
		}
		cp.Stage = "waiting_dns"
		if err = save(ctx, *cp); err != nil {
			return nil, err
		}
	}
	for i := range cp.Challenges {
		ch := &cp.Challenges[i]
		if !ch.Presented {
			receipt, e := dns.Present(ctx, *ch)
			if e != nil {
				return nil, e
			}
			ch.Receipt = receipt
			ch.Presented = true
			if e = save(ctx, *cp); e != nil {
				return nil, e
			}
		}
	}
	if cp.Stage != "issued" && cp.Stage != "complete" {
		for _, ch := range cp.Challenges {
			if err = dns.Wait(ctx, ch); err != nil {
				return nil, err
			}
		}
		if err = p.authenticate(ctx, cp); err != nil {
			return nil, err
		}
		cp.Stage = "validating"
		if err = save(ctx, *cp); err != nil {
			return nil, err
		}
		for {
			ready, e := p.ready(ctx, cp)
			if e != nil {
				return nil, e
			}
			if ready {
				break
			}
			if e = wait(ctx, p.opts.PollInterval); e != nil {
				return nil, e
			}
		}
		cp.Stage = "issued"
		if err = save(ctx, *cp); err != nil {
			return nil, err
		}
	}
	result, err := p.download(ctx, cp)
	if err != nil {
		return nil, err
	}
	if err = verifyResultDomains(result, domains); err != nil {
		return nil, err
	}
	for i := range cp.Challenges {
		ch := &cp.Challenges[i]
		if ch.Cleaned {
			continue
		}
		if err = dns.Cleanup(ctx, *ch); err != nil {
			return result, fmt.Errorf("certificate issued; DNS cleanup requires retry: %w", err)
		}
		ch.Cleaned = true
		ch.Validated = true
		if err = save(ctx, *cp); err != nil {
			return result, err
		}
	}
	cp.Stage = "complete"
	return result, save(ctx, *cp)
}
func (p *cloudProvider) create(ctx context.Context, request Request, domain string, cp *Checkpoint, save SaveCheckpoint) error {
	m := cp.Metadata
	record := func(key string, value any) error {
		if scalar(value) == "" {
			return errors.New("provider did not return order ID")
		}
		m[key] = value
		return save(ctx, *cp)
	}
	call := func(action string, params map[string]any) (map[string]any, error) {
		v, e := p.call(ctx, http.MethodPost, action, params, nil)
		return asMap(v), e
	}
	createOrder := func(action string, params map[string]any, idKey string) (map[string]any, error) {
		marker := "submitted:" + action
		if m[marker] == true {
			return nil, &UnknownError{Message: "证书订单曾提交但未保存远端ID，请核对平台后处理"}
		}
		m[marker] = true
		if err := save(ctx, *cp); err != nil {
			return nil, err
		}
		value, err := call(action, params)
		if err != nil {
			var rejected *RejectedError
			if errors.As(err, &rejected) {
				delete(m, marker)
				if saveErr := save(ctx, *cp); saveErr != nil {
					return nil, saveErr
				}
			}
			return nil, err
		}
		if scalar(value[idKey]) == "" {
			return nil, &UnknownError{Message: "证书平台未返回订单ID，请核对外部结果"}
		}
		m[idKey] = value[idKey]
		delete(m, marker)
		return value, save(ctx, *cp)
	}
	switch p.kind {
	case "tencent":
		if scalar(m["CertificateId"]) != "" {
			return nil
		}
		algorithm, parameter := "RSA", "2048"
		if strings.EqualFold(request.KeyType, "ECC") || strings.EqualFold(request.KeyType, "ECDSA") {
			algorithm = "ECC"
			parameter = "prime256v1"
		}
		_, err := createOrder("ApplyCertificate", map[string]any{"DvAuthMethod": "DNS", "DomainName": domain, "ContactEmail": p.cfg["email"], "CsrEncryptAlgo": algorithm, "CsrKeyParameter": parameter}, "CertificateId")
		if err != nil {
			return err
		}
		return nil
	case "aliyun":
		if scalar(m["InstanceId"]) == "" {
			summary, err := call("GetInstanceSummary", map[string]any{"InstanceType": "TEST"})
			if err != nil {
				return err
			}
			if scalar(summary["InactiveCount"]) == "0" || summary["InactiveCount"] == nil {
				return errors.New("purchase an unused Aliyun test certificate instance first")
			}
			list, err := call("ListInstances", map[string]any{"Status": "inactive", "InstanceType": "TEST"})
			if err != nil {
				return err
			}
			instances := asList(list["InstanceList"])
			if len(instances) == 0 {
				return errors.New("no inactive Aliyun certificate instance")
			}
			if err = record("InstanceId", asMap(instances[0])["InstanceId"]); err != nil {
				return err
			}
		}
		if m["applied"] != true {
			if m["submitted:ApplyCertificate"] == true {
				return &UnknownError{Message: "阿里云证书申请曾提交但未确认，请核对实例状态后处理"}
			}
			contacts, err := call("ListContact", nil)
			if err != nil {
				return err
			}
			list := asList(contacts["ContactList"])
			if len(list) == 0 {
				return errors.New("configure an Aliyun certificate contact first")
			}
			algorithm := "RSA_2048"
			if strings.EqualFold(request.KeyType, "ECC") || strings.EqualFold(request.KeyType, "ECDSA") {
				algorithm = "ECC_256"
			} else if request.KeySize == 3072 {
				algorithm = "RSA_3072"
			}
			if _, err = call("UpdateInstance", map[string]any{"InstanceId": m["InstanceId"], "Domain": domain, "KeyAlgorithm": algorithm, "AutoReissue": "disable", "ContactIdList.1": asMap(list[0])["ContactId"], "ValidateType": "DNS"}); err != nil {
				return err
			}
			m["submitted:ApplyCertificate"] = true
			if err = save(ctx, *cp); err != nil {
				return err
			}
			if _, err = call("ApplyCertificate", map[string]any{"InstanceId": m["InstanceId"]}); err != nil {
				var rejected *RejectedError
				if errors.As(err, &rejected) {
					delete(m, "submitted:ApplyCertificate")
					if saveErr := save(ctx, *cp); saveErr != nil {
						return saveErr
					}
				}
				return err
			}
			m["applied"] = true
			delete(m, "submitted:ApplyCertificate")
			if err = save(ctx, *cp); err != nil {
				return err
			}
		}
		for {
			data, err := call("GetTaskAttribute", map[string]any{"TaskId": m["InstanceId"]})
			if err != nil {
				return err
			}
			switch scalar(data["TaskStatus"]) {
			case "processing":
				if err = wait(ctx, p.opts.PollInterval); err != nil {
					return err
				}
				continue
			case "failed":
				return errors.New(redact(scalar(data["TaskMessage"]), p.cfg))
			}
			break
		}
		return nil
	case "ucloud":
		if scalar(m["CertificateID"]) == "" {
			_, err := createOrder("PurchaseCertificate", map[string]any{"CertificateBrand": "TrustAsia", "CertificateName": "TrustAsiaC1DVFree", "DomainsCount": 1, "ValidYear": 1}, "CertificateID")
			if err != nil {
				return err
			}
		}
		if m["complemented"] != true {
			algorithm, parameter := "RSA", "2048"
			if request.KeySize == 3072 {
				parameter = "3072"
			}
			if strings.EqualFold(request.KeyType, "ECC") || strings.EqualFold(request.KeyType, "ECDSA") {
				algorithm = "ECDSA"
				parameter = "prime384v1"
				if request.KeySize == 256 {
					parameter = "prime256v1"
				}
			}
			params := map[string]any{"CertificateID": m["CertificateID"], "Domains": domain, "CSROnline": 1, "CSREncryptAlgo": algorithm, "CSRKeyParameter": parameter, "CompanyName": "公司名称", "CompanyAddress": "公司地址", "CompanyRegion": "北京", "CompanyCity": "北京", "CompanyCountry": "CN", "CompanyDivision": "部门", "CompanyPhone": p.cfg["phone"], "CompanyPostalCode": "110100", "AdminName": p.cfg["username"], "AdminPhone": p.cfg["phone"], "AdminEmail": p.cfg["email"], "AdminTitle": "职员", "DVAuthMethod": "DNS"}
			if _, err := call("ComplementCSRInfo", params); err != nil {
				return err
			}
			m["complemented"] = true
			return save(ctx, *cp)
		}
		return nil
	case "huoshan":
		if scalar(m["instance_id"]) != "" {
			return nil
		}
		if scalar(m["organization_id"]) == "" {
			value, err := p.call(ctx, http.MethodGet, "CertificateGetOrganization", nil, nil)
			if err != nil {
				return err
			}
			organizations := asList(asMap(value)["content"])
			if len(organizations) == 0 {
				return errors.New("configure a Volcengine organization template first")
			}
			if err = record("organization_id", asMap(organizations[0])["id"]); err != nil {
				return err
			}
		}
		algorithm := strings.ToLower(request.KeyType)
		if algorithm == "ecdsa" {
			algorithm = "ecc"
		}
		marker := "submitted:QuickApplyCertificate"
		if m[marker] == true {
			return &UnknownError{Message: "证书订单曾提交但未保存远端ID，请核对平台后处理"}
		}
		m[marker] = true
		if err := save(ctx, *cp); err != nil {
			return err
		}
		value, err := p.call(ctx, http.MethodPost, "QuickApplyCertificate", map[string]any{"plan": "digicert_free_standard_dv", "common_name": domain, "organization_id": m["organization_id"], "key_alg": algorithm, "validation_type": "dns_txt"}, nil)
		if err != nil {
			var rejected *RejectedError
			if errors.As(err, &rejected) {
				delete(m, marker)
				if saveErr := save(ctx, *cp); saveErr != nil {
					return saveErr
				}
			}
			return err
		}
		delete(m, marker)
		return record("instance_id", value)
	}
	return errors.New("unknown cloud certificate protocol")
}
func (p *cloudProvider) challenges(ctx context.Context, domain string, cp *Checkpoint) error {
	m := cp.Metadata
	add := func(name, kind, value string) {
		if name != "" && value != "" {
			cp.Challenges = append(cp.Challenges, Challenge{Domain: domain, Name: strings.TrimSuffix(name, "."), Type: kind, Value: value})
		}
	}
	switch p.kind {
	case "tencent":
		value, err := p.call(ctx, http.MethodPost, "DescribeCertificate", map[string]any{"CertificateId": m["CertificateId"]}, nil)
		if err != nil {
			return err
		}
		data := asMap(value)
		m["OrderId"] = data["OrderId"]
		for _, v := range asList(asMap(data["DvAuthDetail"])["DvAuths"]) {
			row := asMap(v)
			kind := scalar(row["DvAuthVerifyType"])
			if kind == "" {
				kind = "CNAME"
			}
			add(scalar(row["DvAuthKey"]), kind, scalar(row["DvAuthValue"]))
		}
	case "aliyun":
		value, err := p.call(ctx, http.MethodPost, "GetInstanceDetail", map[string]any{"InstanceId": m["InstanceId"]}, nil)
		if err != nil {
			return err
		}
		for _, v := range asList(asMap(value)["DomainValidationList"]) {
			row := asMap(v)
			add(scalar(row["ValidationKey"])+"."+scalar(row["RootDomain"]), scalar(row["ValidationType"]), scalar(row["ValidationValue"]))
		}
	case "ucloud":
		value, err := p.call(ctx, http.MethodPost, "GetDVAuthInfo", map[string]any{"CertificateID": m["CertificateID"]}, nil)
		if err != nil {
			return err
		}
		for _, v := range asList(asMap(value)["Auths"]) {
			row := asMap(v)
			kind := "CNAME"
			if row["AuthType"] == "DNS_TXT" {
				kind = "TXT"
			}
			add(scalar(row["AuthKey"]), kind, scalar(row["AuthValue"]))
		}
	case "huoshan":
		value, err := p.call(ctx, http.MethodGet, "CertificateGetDcvParam", map[string]any{"instance_id": m["instance_id"]}, nil)
		if err != nil {
			return err
		}
		data := asMap(value)
		kind := "TXT"
		if data["validation_type"] == "dns_cname" {
			kind = "CNAME"
		}
		for _, v := range asList(data["domains_to_be_validated"]) {
			row := asMap(v)
			add(scalar(row["validation_domain"]), kind, scalar(row["value"]))
		}
	}
	if len(cp.Challenges) == 0 {
		return errors.New("cloud certificate DNS validation is not ready; retry this checkpoint")
	}
	return nil
}
func (p *cloudProvider) authenticate(ctx context.Context, cp *Checkpoint) error {
	switch p.kind {
	case "tencent":
		params := map[string]any{"CertificateId": cp.Metadata["CertificateId"]}
		value, err := p.call(ctx, http.MethodPost, "DescribeCertificate", params, nil)
		if err != nil {
			return err
		}
		status := scalar(asMap(value)["Status"])
		if status == "0" || status == "4" {
			_, err = p.call(ctx, http.MethodPost, "CompleteCertificate", params, nil)
		}
		return err
	case "huoshan":
		_, err := p.call(ctx, http.MethodPost, "CertificateProgressInstanceOrder", map[string]any{"action": ""}, map[string]any{"instance_id": cp.Metadata["instance_id"]})
		return err
	}
	return nil
}
func (p *cloudProvider) ready(ctx context.Context, cp *Checkpoint) (bool, error) {
	var action string
	params := map[string]any{}
	method := http.MethodPost
	switch p.kind {
	case "tencent":
		action = "DescribeCertificate"
		params["CertificateId"] = cp.Metadata["CertificateId"]
	case "aliyun":
		action = "GetInstanceDetail"
		params["InstanceId"] = cp.Metadata["InstanceId"]
	case "ucloud":
		action = "GetCertificateDetailInfo"
		params["CertificateID"] = cp.Metadata["CertificateID"]
	case "huoshan":
		action = "CertificateGetInstance"
		params["instance_id"] = cp.Metadata["instance_id"]
		method = http.MethodGet
	}
	value, err := p.call(ctx, method, action, params, nil)
	if err != nil {
		return false, err
	}
	data := asMap(value)
	switch p.kind {
	case "tencent":
		status := scalar(data["Status"])
		if status == "2" {
			return false, errors.New("Tencent certificate review failed")
		}
		return status == "1", nil
	case "aliyun":
		status := scalar(data["Status"])
		if status == "closed" {
			return false, errors.New("Aliyun certificate review failed")
		}
		return status == "normal", nil
	case "ucloud":
		status := scalar(asMap(data["CertificateInfo"])["StateCode"])
		if status == "REJECTED" || status == "SECURITY_REVIEW_FAILED" {
			return false, errors.New("UCloud certificate review failed")
		}
		return status == "COMPLETED" || status == "RENEWED", nil
	case "huoshan":
		content := asList(data["content"])
		if len(content) == 0 {
			return false, errors.New("Volcengine instance was not found")
		}
		instance := asMap(content[0])
		if scalar(instance["order_status"]) == "302" {
			return false, errors.New("Volcengine certificate application failed")
		}
		return scalar(instance["order_status"]) == "300" && scalar(instance["certificate_exist"]) == "1", nil
	}
	return false, nil
}
func (p *cloudProvider) download(ctx context.Context, cp *Checkpoint) (*Result, error) {
	m := cp.Metadata
	switch p.kind {
	case "aliyun":
		value, err := p.call(ctx, http.MethodPost, "GetInstanceDetail", map[string]any{"InstanceId": m["InstanceId"]}, nil)
		if err != nil {
			return nil, err
		}
		id := asMap(value)["CertificateId"]
		if scalar(id) == "" {
			return nil, errors.New("Aliyun certificate ID missing")
		}
		value, err = p.call(ctx, http.MethodPost, "GetUserCertificateDetail", map[string]any{"CertId": id}, nil)
		if err != nil {
			return nil, err
		}
		data := asMap(value)
		return ParseResult(scalar(data["Cert"]), scalar(data["Key"]))
	case "huoshan":
		value, err := p.call(ctx, http.MethodGet, "CertificateGetInstance", map[string]any{"instance_id": m["instance_id"]}, nil)
		if err != nil {
			return nil, err
		}
		content := asList(asMap(value)["content"])
		if len(content) == 0 {
			return nil, errors.New("Volcengine certificate instance missing")
		}
		cert := asMap(asMap(asMap(content[0])["ssl"])["certificate"])
		var chain strings.Builder
		for _, v := range asList(cert["chain"]) {
			chain.WriteString(scalar(v))
			chain.WriteByte('\n')
		}
		return ParseResult(chain.String(), scalar(cert["private_key"]))
	case "tencent":
		if _, err := p.call(ctx, http.MethodPost, "ModifyCertificatesExpiringNotificationSwitch", map[string]any{"CertificateIds": []any{m["CertificateId"]}, "SwitchStatus": 1}, nil); err != nil {
			return nil, err
		}
		value, err := p.call(ctx, http.MethodPost, "DescribeDownloadCertificateUrl", map[string]any{"CertificateId": m["CertificateId"], "ServiceType": "nginx"}, nil)
		if err != nil {
			return nil, err
		}
		return p.downloadZIP(ctx, scalar(asMap(value)["DownloadCertificateUrl"]), ".crt")
	case "ucloud":
		value, err := p.call(ctx, http.MethodPost, "DownloadCertificate", map[string]any{"CertificateID": m["CertificateID"]}, nil)
		if err != nil {
			return nil, err
		}
		return p.downloadZIP(ctx, scalar(asMap(value)["CertificateUrl"]), ".pem")
	}
	return nil, errors.New("unknown certificate download protocol")
}
func (p *cloudProvider) downloadZIP(ctx context.Context, endpoint, extension string) (*Result, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("invalid certificate download URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, errors.New("certificate download failed")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	return ParseCertificateZIP(raw, extension)
}

// ParseCertificateZIP reads bounded PEM entries in memory; no archive path is extracted.
func ParseCertificateZIP(raw []byte, extension string) (*Result, error) {
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, errors.New("invalid certificate ZIP")
	}
	if len(raw) > 16<<20 || len(reader.File) > 64 {
		return nil, errors.New("certificate ZIP exceeds archive limits")
	}
	keys, chains := []string{}, []string{}
	total := uint64(0)
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if path.Clean(file.Name) != file.Name || strings.HasPrefix(file.Name, "/") || strings.HasPrefix(file.Name, "../") {
			return nil, errors.New("unsafe ZIP entry")
		}
		ext := strings.ToLower(path.Ext(file.Name))
		if ext != ".key" && ext != extension {
			continue
		}
		total += file.UncompressedSize64
		if file.UncompressedSize64 > 4<<20 || total > 16<<20 {
			return nil, errors.New("certificate ZIP entry too large")
		}
		stream, err := file.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(stream, (4<<20)+1))
		stream.Close()
		if err != nil {
			return nil, err
		}
		if len(data) > 4<<20 {
			return nil, errors.New("certificate ZIP entry exceeds actual limit")
		}
		if ext == ".key" {
			keys = append(keys, string(data))
		} else {
			chains = append(chains, string(data))
		}
	}
	for _, chain := range chains {
		for _, key := range keys {
			if result, err := ParseResult(chain, key); err == nil {
				return result, nil
			}
		}
	}
	return nil, errors.New("ZIP contains no matching certificate and private key")
}
func cloudKeyRequest(kind string, request Request) (Request, error) {
	switch strings.ToUpper(request.KeyType) {
	case "", "RSA":
		request.KeyType = "RSA"
		if request.KeySize == 0 {
			request.KeySize = 2048
		}
	case "ECC", "ECDSA", "EC":
		request.KeyType = "ECC"
		if request.KeySize == 0 {
			request.KeySize = 256
		}
	default:
		return request, errors.New("cloud certificate key type must be RSA or ECC")
	}
	valid := request.KeyType == "RSA" && request.KeySize == 2048 || request.KeyType == "ECC" && request.KeySize == 256
	if (kind == "aliyun" || kind == "ucloud") && request.KeyType == "RSA" && request.KeySize == 3072 {
		valid = true
	}
	if kind == "ucloud" && request.KeyType == "ECC" && request.KeySize == 384 {
		valid = true
	}
	if !valid {
		return request, errors.New("requested key size is not supported by this cloud issuer")
	}
	return request, nil
}
func (p *cloudProvider) Revoke(ctx context.Context, cp *Checkpoint, chain string) error {
	if cp == nil || cp.Metadata == nil {
		return errors.New("certificate checkpoint is required")
	}
	if cp.Provider != "" && cp.Provider != p.kind {
		return errors.New("checkpoint belongs to another provider")
	}
	key := map[string]string{"tencent": "CertificateId", "aliyun": "InstanceId", "ucloud": "CertificateID", "huoshan": "instance_id"}[p.kind]
	if scalar(cp.Metadata[key]) == "" {
		return errors.New("certificate checkpoint has no remote order ID")
	}
	if cp.Stage == "revoked" {
		return cleanupCheckpoint(ctx, cp, p.opts)
	}
	if p.kind == "tencent" && p.opts.SaveCheckpoint == nil {
		return errors.New("revocation requires checkpoint persistence")
	}
	if cp.Metadata["revoke_requested"] != true {
		var action string
		params := map[string]any{}
		extra := map[string]any{}
		switch p.kind {
		case "tencent":
			action = "RevokeCertificate"
			params["CertificateId"] = cp.Metadata[key]
		case "aliyun":
			action = "RevokeCertificate"
			params["InstanceId"] = cp.Metadata[key]
		case "ucloud":
			action = "RevokeCertificate"
			params["CertificateID"] = cp.Metadata[key]
			params["Reason"] = "业务终止"
		case "huoshan":
			action = "CertificateProgressInstanceOrder"
			params["action"] = "revoke"
			params["reason"] = "关联域名错误"
			extra["instance_id"] = cp.Metadata[key]
		}
		value, err := p.call(ctx, http.MethodPost, action, params, extra)
		if err != nil {
			return err
		}
		if p.kind == "tencent" {
			for _, v := range asList(asMap(value)["RevokeDomainValidateAuths"]) {
				row := asMap(v)
				ch := Challenge{Domain: scalar(row["DomainValidateAuthDomain"]), Name: scalar(row["DomainValidateAuthKey"]), Type: "TXT", Value: scalar(row["DomainValidateAuthValue"]), URL: "revocation"}
				if ch.Name == "" || ch.Value == "" {
					return errors.New("Tencent returned invalid revocation DNS challenge")
				}
				cp.Challenges = append(cp.Challenges, ch)
			}
		}
		cp.Metadata["revoke_requested"] = true
		cp.Stage = "revoking"
		if p.opts.SaveCheckpoint != nil {
			if err = p.opts.SaveCheckpoint(ctx, *cp); err != nil {
				return err
			}
		}
	}
	if p.kind == "tencent" {
		for i := range cp.Challenges {
			ch := &cp.Challenges[i]
			if ch.URL != "revocation" || ch.Cleaned {
				continue
			}
			if p.opts.DNS == nil {
				return errors.New("revocation requires DNS verification callback")
			}
			if !ch.Presented {
				receipt, err := p.opts.DNS.Present(ctx, *ch)
				if err != nil {
					return err
				}
				ch.Receipt = receipt
				ch.Presented = true
				if err = p.opts.SaveCheckpoint(ctx, *cp); err != nil {
					return err
				}
			}
			if err := p.opts.DNS.Wait(ctx, *ch); err != nil {
				return err
			}
		}
		for {
			value, err := p.call(ctx, http.MethodGet, "DescribeCertificate", map[string]any{"CertificateId": cp.Metadata[key]}, nil)
			if err != nil {
				return err
			}
			status := scalar(asMap(value)["Status"])
			if status == "10" {
				break
			}
			if status != "1" && status != "9" {
				return fmt.Errorf("Tencent revocation requires review (status %s)", status)
			}
			if err = wait(ctx, p.opts.PollInterval); err != nil {
				return err
			}
		}
	}
	if err := cleanupCheckpoint(ctx, cp, p.opts); err != nil {
		return err
	}
	cp.Stage = "revoked"
	if p.opts.SaveCheckpoint != nil {
		return p.opts.SaveCheckpoint(ctx, *cp)
	}
	return nil
}
func (p *cloudProvider) Cancel(ctx context.Context, cp *Checkpoint) error {
	if cp == nil {
		return errors.New("certificate checkpoint is required")
	}
	if cp.Stage == "cancelled" {
		return nil
	}
	if cp.Metadata == nil {
		cp.Metadata = map[string]any{}
	}
	var action string
	params := map[string]any{}
	extra := map[string]any{}
	switch p.kind {
	case "tencent":
		action = "CancelAuditCertificate"
		params["CertificateId"] = cp.Metadata["CertificateId"]
	case "aliyun":
		value, err := p.call(ctx, http.MethodPost, "GetInstanceDetail", map[string]any{"InstanceId": cp.Metadata["InstanceId"]}, nil)
		if err != nil {
			return err
		}
		if asMap(value)["Status"] != "pending" {
			return cleanupCheckpoint(ctx, cp, p.opts)
		}
		action = "CancelPendingCertificate"
		params["InstanceId"] = cp.Metadata["InstanceId"]
	case "ucloud":
		action = "CancelCertificateOrder"
		params["CertificateID"] = cp.Metadata["CertificateID"]
	case "huoshan":
		action = "CertificateProgressInstanceOrder"
		params["action"] = "cancel"
		extra["instance_id"] = cp.Metadata["instance_id"]
	}
	if cp.Metadata["cancel_requested"] != true {
		if _, err := p.call(ctx, http.MethodPost, action, params, extra); err != nil {
			return err
		}
		cp.Metadata["cancel_requested"] = true
		if p.opts.SaveCheckpoint != nil {
			if err := p.opts.SaveCheckpoint(ctx, *cp); err != nil {
				return err
			}
		}
	}
	if p.kind == "ucloud" && cp.Metadata["cancel_deleted"] != true {
		params["CertificateMode"] = "purchase"
		_, err := p.call(ctx, http.MethodPost, "DeleteSSLCertificate", params, nil)
		if err != nil {
			return err
		}
		cp.Metadata["cancel_deleted"] = true
		if p.opts.SaveCheckpoint != nil {
			if err := p.opts.SaveCheckpoint(ctx, *cp); err != nil {
				return err
			}
		}
	}
	if err := cleanupCheckpoint(ctx, cp, p.opts); err != nil {
		return err
	}
	cp.Stage = "cancelled"
	if p.opts.SaveCheckpoint != nil {
		return p.opts.SaveCheckpoint(ctx, *cp)
	}
	return nil
}
