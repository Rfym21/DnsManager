package deploy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func appendCloudWireCases(t *testing.T, cases *[]deployWireCase, chain, key string) {
	t.Helper()
	add := func(kind string, cfg, target map[string]string, steps ...deployWireStep) {
		*cases = append(*cases, deployWireCase{kind: kind, cfg: cfg, target: target, steps: steps})
	}
	cloudKeys := map[string]string{"AccessKeyId": "fixture-id", "SecretAccessKey": "fixture-secret"}
	add("huawei", cloudKeys, map[string]string{"product": "cdn", "domain": "example.com"}, wireWrite("PUT", "/v1.1/cdn/configuration/domains/example.com/configs", `{}`, map[string]string{"configs.https.certificate_value": chain, "configs.https.private_key": key, "configs.https.https_status": "on"}))
	add("baidu", cloudKeys, map[string]string{"product": "cdn", "domain": "example.com"}, wireWrite("PUT", "/v2/example.com/certificates", `{"certId":"9"}`, map[string]string{"httpsEnable": "ON", "certificate.certServerData": chain, "certificate.certPrivateData": key}))
	ctCreate := wireWrite("POST", "/v1/cert/creat-cert", `{"statusCode":100000,"returnObj":{}}`, map[string]string{"key": key, "certs": chain})
	ctBind := wireStep("POST", "/v1/domain/update-domain", `{"statusCode":100000,"returnObj":{}}`)
	ctBind.fields = map[string]string{"domain": "example.com", "https_status": "on"}
	add("ctyun", cloudKeys, map[string]string{"product": "cdn", "domain": "example.com"}, ctCreate, ctBind)
	volcImport := wireWrite("POST", "/", `{"Result":{"InstanceId":"9"}}`, map[string]string{"CertificateInfo.CertificateChain": chain, "CertificateInfo.PrivateKey": key})
	volcImport.query = map[string]string{"Action": "ImportCertificate", "Version": "2024-10-01"}
	volcUpdate := wireStep("POST", "/", `{"Result":{}}`)
	volcUpdate.query = map[string]string{"Action": "CertificateUpdateInstance", "Version": "2024-10-01"}
	volcUpdate.fields = map[string]string{"InstanceId": "9", "Options.ExpiredNotice": "Disabled"}
	volcBind := wireStep("POST", "/", `{"Result":{"DeployResult":[{"Status":"success"}]}}`)
	volcBind.query = map[string]string{"Action": "BatchDeployCert", "Version": "2021-03-01"}
	volcBind.fields = map[string]string{"CertId": "9", "Domain": "example.com"}
	add("huoshan", cloudKeys, map[string]string{"product": "cdn", "domain": "example.com"}, volcImport, volcUpdate, volcBind)
	ksList := wireStep("GET", "/2019-06-01/domain/GetCdnDomains", `{"Domains":[{"DomainName":"example.com","DomainId":"domain-9"}]}`)
	ksList.query = map[string]string{"PageSize": "100", "PageNumber": "1"}
	ksList.headers = map[string]string{"X-Action": "GetCdnDomains", "X-Version": "2019-06-01"}
	ksBind := wireWrite("POST", "/2016-09-01/cert/ConfigCertificate", `{"CertificateId":"9"}`, map[string]string{"Enable": "on", "DomainIds": "domain-9", "ServerCertificate": chain, "PrivateKey": key})
	ksBind.headers = map[string]string{"X-Action": "ConfigCertificate", "X-Version": "2016-09-01"}
	add("ksyun", cloudKeys, map[string]string{"domain": "example.com"}, ksList, ksBind)
	westInfo := wireStep("POST", "/vhost/", `{"result":200,"data":{"SSLEnabled":true}}`)
	westInfo.fields = map[string]string{"act": "vhostssl", "sitename": "fixture-site", "cmd": "info"}
	westImport := wireWrite("POST", "/vhost/", `{"result":200,"data":{}}`, map[string]string{"act": "vhostssl", "sitename": "fixture-site", "cmd": "import", "keycontent": key, "certcontent": chain})
	add("west", map[string]string{"username": "fixture-user", "api_password": "fixture-secret"}, map[string]string{"sitename": "fixture-site"}, westInfo, westImport, westInfo)
	add("wangsu", map[string]string{"username": "fixture-user", "apiKey": "fixture-secret"}, map[string]string{"product": "certificate", "cert_id": "9"}, wireWrite("PUT", "/api/certificate/9", `{}`, map[string]string{"certificate": chain, "privateKey": key}))
	qList := wireStep("GET", "/sslcert", `{"certs":[]}`)
	qList.query = map[string]string{"marker": "", "limit": "100"}
	qUpload := wireWrite("POST", "/sslcert", `{"certID":"9"}`, map[string]string{"ca": chain, "pri": key, "common_name": "example.com"})
	qDomain := wireStep("GET", "/domain/example.com", `{"https":{}}`)
	qBind := wireStep("PUT", "/domain/example.com/sslize", `{}`)
	qBind.fields = map[string]string{"certid": "9"}
	add("qiniu", map[string]string{"AccessKey": "fixture-id", "SecretKey": "fixture-secret"}, map[string]string{"product": "cdn", "domain": "example.com"}, qList, qUpload, qDomain, qBind)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		t.Fatal(e)
	}
	name := strings.ReplaceAll(strings.ReplaceAll(leaf.Subject.CommonName, "*", ""), ".", "") + fmt.Sprintf("-%d", leaf.NotBefore.Unix())
	uAdd := wireWrite("POST", "/", `{"RetCode":0}`, map[string]string{"Action": "AddCertificate", "UserCert": chain, "PrivateKey": key})
	uDomain := wireStep("POST", "/", `{"RetCode":0,"DomainList":[{"Domain":"example.com","HttpsStatusCn":"enable","HttpsStatusAbroad":"enable"}]}`)
	uDomain.fields = map[string]string{"Action": "GetUcdnDomainConfig", "DomainId.0": "domain-9"}
	uCert := wireStep("POST", "/", `{"RetCode":0,"CertList":[{"CertId":"9","CertName":"`+name+`"}]}`)
	uCert.fields = map[string]string{"Action": "GetCertificateBaseInfoList", "Domain": "example.com"}
	uBind := wireStep("POST", "/", `{"RetCode":0}`)
	uBind.fields = map[string]string{"Action": "UpdateUcdnDomainHttpsConfigV2", "DomainId": "domain-9", "CertId": "9", "CertType": "ucdn", "HttpsStatusCn": "enable", "HttpsStatusAbroad": "enable"}
	add("ucloud", map[string]string{"PublicKey": "fixture-id", "PrivateKey": "fixture-secret"}, map[string]string{"domain_id": "domain-9"}, uAdd, uDomain, uCert, uBind)
	s3Cert := wireWrite("PUT", "/fixture/cert.pem", "", nil)
	s3Cert.check = func(t *testing.T, _ *http.Request, raw []byte) {
		if string(raw) != chain {
			t.Error("S3 certificate bytes mismatch")
		}
	}
	s3Key := wireStep("PUT", "/fixture/key.pem", "")
	s3Key.check = func(t *testing.T, _ *http.Request, raw []byte) {
		if string(raw) != key {
			t.Error("S3 private key bytes mismatch")
		}
	}
	add("s3storage", cloudKeys, map[string]string{"bucket": "fixture", "cert_path": "cert.pem", "key_path": "key.pem"}, s3Cert, s3Key)
	awsImport := wireWrite("POST", "/", `{"CertificateArn":"arn:fixture:9"}`, map[string]string{"Certificate": base64.StdEncoding.EncodeToString([]byte(chain)), "PrivateKey": base64.StdEncoding.EncodeToString([]byte(key)), "CertificateArn": "arn:fixture:9"})
	awsImport.headers = map[string]string{"X-Amz-Target": "CertificateManager.ImportCertificate"}
	add("aws", cloudKeys, map[string]string{"product": "acm", "acm_arn": "arn:fixture:9"}, awsImport)
	aliList := wireStep("POST", "/", `{"CertificateOrderList":[]}`)
	aliList.fields = map[string]string{"Action": "ListUserCertificateOrder"}
	aliUpload := wireWrite("POST", "/", `{"CertId":9}`, map[string]string{"Action": "UploadUserCertificate", "Cert": chain, "Key": key})
	add("aliyun", map[string]string{"AccessKeyId": "fixture-id", "AccessKeySecret": "fixture-secret"}, map[string]string{"product": "upload"}, aliList, aliUpload)
	tencentUpload := wireWrite("POST", "/", `{"Response":{"CertificateId":"9"}}`, map[string]string{"CertificatePublicKey": chain, "CertificatePrivateKey": key, "CertificateType": "SVR"})
	tencentUpload.headers = map[string]string{"X-TC-Action": "UploadCertificate", "X-TC-Version": "2019-12-05"}
	tencentNotification := wireStep("POST", "/", `{"Response":{}}`)
	tencentNotification.headers = map[string]string{"X-TC-Action": "ModifyCertificatesExpiringNotificationSwitch"}
	add("tencent", map[string]string{"SecretId": "fixture-id", "SecretKey": "fixture-secret"}, map[string]string{"product": "upload"}, tencentUpload, tencentNotification)
	kubeGet := wireStep("GET", "/api/v1/namespaces/fixture/secrets/fixture-tls", `{"metadata":{"resourceVersion":"9"}}`)
	kubePatch := wireWrite("PATCH", "/api/v1/namespaces/fixture/secrets/fixture-tls", `{}`, nil)
	kubePatch.headers = map[string]string{"Content-Type": "application/merge-patch+json"}
	kubePatch.check = func(t *testing.T, req *http.Request, raw []byte) {
		body := wireBody(t, req, raw)
		if text(wireField(body, "data.tls.crt")) != base64.StdEncoding.EncodeToString([]byte(chain)) || text(wireField(body, "data.tls.key")) != base64.StdEncoding.EncodeToString([]byte(key)) || text(wireField(body, "metadata.resourceVersion")) != "9" {
			t.Error("Kubernetes Secret payload mismatch")
		}
	}
	add("k8s", map[string]string{}, map[string]string{"namespace": "fixture", "secret_name": "fixture-tls"}, kubeGet, kubePatch)
	private, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	challenge := map[string]any{"version": 1, "algorithm": "RSA-OAEP-256+A256GCM", "keyId": "fixture-key", "challengeId": "fixture-challenge", "publicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
	challengeResponse, _ := json.Marshal(map[string]any{"success": true, "data": challenge})
	uniChallenge := wireStep("POST", "/client", string(challengeResponse))
	uniChallenge.check = func(t *testing.T, req *http.Request, raw []byte) {
		checkUniWireBusiness(t, req, raw, "uni-id-co", "createPasswordChallenge", nil)
	}
	uniLogin := wireStep("POST", "/client", `{"success":true,"data":{"errCode":0,"newToken":{"token":"fixture-token"}}}`)
	uniLogin.check = func(t *testing.T, req *http.Request, raw []byte) {
		checkUniWireBusiness(t, req, raw, "uni-id-co", "login", private)
	}
	uniHost := wireStep("POST", "/client", `{"success":true,"data":{"code":0,"data":{"ret":0,"data":{"token":"fixture-host-token"}}}}`)
	uniHost.headers = map[string]string{"X-Client-Token": "fixture-token"}
	uniHost.check = func(t *testing.T, req *http.Request, raw []byte) {
		checkUniWireBusiness(t, req, raw, "uni-cloud-kernel", "user/getUserToken", nil)
	}
	uniWrite := wireWrite("POST", "/unicloud/api/host/create-domain-with-cert", `{"ret":0}`, map[string]string{"provider": "aliyun", "spaceId": "fixture-space", "domain": "example.com", "cert": strings.ReplaceAll(url.QueryEscape(chain), "+", "%20"), "key": strings.ReplaceAll(url.QueryEscape(key), "+", "%20")})
	uniWrite.headers = map[string]string{"Token": "fixture-host-token"}
	add("unicloud", map[string]string{"username": "fixture@example.com", "password": "fixture-secret"}, map[string]string{"spaceId": "fixture-space", "provider": "aliyun", "domains": "example.com"}, uniChallenge, uniLogin, uniHost, uniWrite)
}
