package deploy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func wireSHA1(raw []byte) []byte { sum := sha1.Sum(raw); return sum[:] }

func checkDeploymentWireAuth(t *testing.T, kind string, cfg map[string]string, req *http.Request, raw []byte) {
	t.Helper()
	check := func(name, want string) {
		if req.Header.Get(name) != want {
			t.Errorf("%s auth header %s mismatch", kind, name)
		}
	}
	switch kind {
	case "btpanel", "btwin":
		form, _ := url.ParseQuery(string(raw))
		ts := form.Get("request_time")
		if ts != "1791853323" || form.Get("request_token") != wireMD5(ts+wireMD5(cfg["key"])) {
			t.Error("BT signed timestamp mismatch")
		}
	case "btwaf":
		ts := req.Header.Get("waf_request_time")
		check("waf_request_token", wireMD5(ts+wireMD5(cfg["key"])))
	case "mwpanel":
		check("app-id", cfg["appid"])
		check("app-secret", cfg["appsecret"])
	case "ratpanel", "acepanel":
		ts := req.Header.Get("X-Timestamp")
		canonical := req.Method + "\n" + req.URL.Path + "\n" + req.URL.RawQuery + "\n" + wireSHA(raw)
		sign := hex.EncodeToString(wireHMAC("sha256", []byte(cfg["token"]), "HMAC-SHA256\n"+ts+"\n"+wireSHA([]byte(canonical))))
		check("Authorization", "HMAC-SHA256 Credential="+cfg["id"]+", Signature="+sign)
	case "xp":
		check("XP-API-KEY", cfg["apikey"])
	case "lucky":
		check("openToken", cfg["opentoken"])
	case "safeline":
		check("X-SLCE-API-TOKEN", cfg["token"])
	case "opanel":
		ts := req.Header.Get("1Panel-Timestamp")
		check("1Panel-Token", wireMD5("1panel"+cfg["key"]+ts))
	case "proxmox":
		check("Authorization", "PVEAPIToken="+cfg["api_user"]+"="+cfg["api_key"])
	case "directadmin":
		user, pass, ok := req.BasicAuth()
		if !ok || user != cfg["username"] || pass != cfg["password"] {
			t.Error("DirectAdmin basic authentication mismatch")
		}
	case "uusec":
		if req.URL.Path != "/api/v1/users/login" {
			check("Authorization", "Bearer fixture-token")
		}
	case "gcore":
		check("Authorization", "APIKey "+cfg["apikey"])
	case "cachefly":
		check("x-cf-authorization", "Bearer "+cfg["apikey"])
	case "axisnow":
		check("Authorization", "Bearer "+cfg["token"])
	case "rainyun":
		check("x-api-key", cfg["apikey"])
	case "cdnfly":
		check("api-key", cfg["api_key"])
		check("api-secret", cfg["api_secret"])
	case "lecdn":
		check("Authorization", cfg["api_key"])
	case "goedge":
		if req.URL.Path != "/APIAccessTokenService/getAPIAccessToken" {
			check("X-Edge-Access-Token", "fixture-token")
		}
	case "kuocai":
		if req.URL.Path != "/login/loginUser" {
			check("Cookie", "kuocai_cdn_token=fixture-token")
		}
	case "doge":
		check("Authorization", "TOKEN "+cfg["AccessKey"]+":"+hex.EncodeToString(wireHMAC("sha1", []byte(cfg["SecretKey"]), req.URL.RequestURI()+"\n"+string(raw))))
	case "nginxproxymanager":
		if req.URL.Path != "/api/tokens" {
			check("Authorization", "Bearer fixture-token")
		}
	case "amh":
		form, _ := url.ParseQuery(string(raw))
		if req.URL.Query().Get("c") == "amapi" {
			want := hex.EncodeToString(wireHMAC("sha256", []byte(cfg["apikey"]), "amapi_expires="+form.Get("amapi_expires")))
			if form.Get("amapi_sign") != want {
				t.Error("AMH API HMAC mismatch")
			}
		}
		check("Cookie", "PHPSESSID="+hex.EncodeToString(wireHMAC("md5", []byte(cfg["apikey"]), "php_sessid="+cfg["apikey"])))
	case "west":
		form, _ := url.ParseQuery(string(raw))
		if form.Get("username") != cfg["username"] || form.Get("token") != wireMD5(cfg["username"]+cfg["api_password"]+form.Get("time")) {
			t.Error("West signature mismatch")
		}
	case "qiniu":
		check("Authorization", "QBox "+cfg["AccessKey"]+":"+base64.URLEncoding.EncodeToString(wireHMAC("sha1", []byte(cfg["SecretKey"]), req.URL.RequestURI()+"\n")))
	case "ucloud":
		body := wireBody(t, req, raw)
		names := []string{}
		for name := range body {
			if name != "Signature" {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		canonical := ""
		for _, name := range names {
			canonical += name + text(body[name])
		}
		if text(body["Signature"]) != hex.EncodeToString(wireSHA1([]byte(canonical+cfg["PrivateKey"]))) {
			t.Error("UCloud parameter signature mismatch")
		}
	case "wangsu":
		date := req.Header.Get("Date")
		user, signature, ok := req.BasicAuth()
		if !ok || user != cfg["username"] || signature != base64.StdEncoding.EncodeToString(wireHMAC("sha1", []byte(cfg["apiKey"]), date)) {
			t.Error("Wangsu date signature mismatch")
		}
	case "huawei", "baidu":
		checkRegionalWireAuth(t, kind, cfg, req, raw)
	case "ctyun":
		keys := []string{"content-type", "ctyun-eop-request-id", "eop-date", "host"}
		if len(raw) == 0 {
			keys = keys[1:]
		}
		sort.Strings(keys)
		canonical := ""
		for _, name := range keys {
			value := req.Header.Get(name)
			if name == "host" {
				value = req.Host
			}
			canonical += name + ":" + value + "\n"
		}
		date := req.Header.Get("eop-date")
		k := wireHMAC("sha256", wireHMAC("sha256", wireHMAC("sha256", []byte(cfg["SecretAccessKey"]), date), cfg["AccessKeyId"]), date[:8])
		signature := base64.StdEncoding.EncodeToString(wireHMAC("sha256", k, canonical+"\n"+strings.ReplaceAll(req.URL.Query().Encode(), "+", "%20")+"\n"+wireSHA(raw)))
		check("Eop-Authorization", cfg["AccessKeyId"]+" Headers="+strings.Join(keys, ";")+" Signature="+signature)
	case "huoshan":
		service, region := "cdn", "cn-north-1"
		if req.URL.Query().Get("Version") == "2024-10-01" {
			service, region = "certificate_service", "cn-beijing"
		}
		date := req.Header.Get("x-date")
		headers := "content-type:application/json\nhost:" + req.Host + "\nx-date:" + date + "\n"
		signed := "content-type;host;x-date"
		canonical := req.Method + "\n/\n" + strings.ReplaceAll(req.URL.Query().Encode(), "+", "%20") + "\n" + headers + "\n" + signed + "\n" + wireSHA(raw)
		scope := date[:8] + "/" + region + "/" + service + "/request"
		k := wireHMAC("sha256", wireHMAC("sha256", wireHMAC("sha256", wireHMAC("sha256", []byte(cfg["SecretAccessKey"]), date[:8]), region), service), "request")
		signature := hex.EncodeToString(wireHMAC("sha256", k, "HMAC-SHA256\n"+date+"\n"+scope+"\n"+wireSHA([]byte(canonical))))
		check("Authorization", "HMAC-SHA256 Credential="+cfg["AccessKeyId"]+"/"+scope+", SignedHeaders="+signed+", Signature="+signature)
	case "aws", "ksyun", "s3storage":
		service, region := "acm", "us-east-1"
		if kind == "ksyun" {
			service, region = "cdn", "cn-shanghai-2"
		}
		if kind == "s3storage" {
			service = "s3"
		}
		verifyWireAWS(t, req, raw, cfg, service, region)
	case "tencent":
		date := "2026-10-13"
		timestamp := req.Header.Get("X-TC-Timestamp")
		scope := date + "/ssl/tc3_request"
		canonical := "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:" + req.Host + "\n\ncontent-type;host\n" + wireSHA(raw)
		k := wireHMAC("sha256", wireHMAC("sha256", wireHMAC("sha256", []byte("TC3"+cfg["SecretKey"]), date), "ssl"), "tc3_request")
		sign := hex.EncodeToString(wireHMAC("sha256", k, "TC3-HMAC-SHA256\n"+timestamp+"\n"+scope+"\n"+wireSHA([]byte(canonical))))
		check("Authorization", "TC3-HMAC-SHA256 Credential="+cfg["SecretId"]+"/"+scope+", SignedHeaders=content-type;host, Signature="+sign)
	case "aliyun":
		values, _ := url.ParseQuery(string(raw))
		signature := values.Get("Signature")
		values.Del("Signature")
		canonical := strings.ReplaceAll(values.Encode(), "+", "%20")
		signed := req.Method + "&%2F&" + strings.ReplaceAll(url.QueryEscape(canonical), "+", "%20")
		if signature != base64.StdEncoding.EncodeToString(wireHMAC("sha1", []byte(cfg["AccessKeySecret"]+"&"), signed)) {
			t.Error("Aliyun RPC signature mismatch")
		}
	case "k8s":
		check("Authorization", "Bearer fixture-token")
	case "unicloud":
		if req.URL.Path == "/client" {
			body := wireBody(t, req, raw)
			signKey := "ba461799-fde8-429f-8cc4-4b6d306e2339"
			if text(body["spaceId"]) != "uni-id-server" {
				signKey = "4c1f7fbf-c732-42b0-ab10-4634a8bbe834"
			}
			names := []string{}
			for name := range body {
				names = append(names, name)
			}
			sort.Strings(names)
			parts := []string{}
			for _, name := range names {
				parts = append(parts, name+"="+text(body[name]))
			}
			check("X-Serverless-Sign", hex.EncodeToString(wireHMAC("md5", []byte(signKey), strings.Join(parts, "&"))))
		}
	}
}

func checkRegionalWireAuth(t *testing.T, kind string, cfg map[string]string, req *http.Request, raw []byte) {
	t.Helper()
	dateHeader, date := "x-sdk-date", req.Header.Get("x-sdk-date")
	if kind == "baidu" {
		dateHeader, date = "x-bce-date", req.Header.Get("x-bce-date")
	}
	names := []string{"host", dateHeader}
	if len(raw) > 0 {
		names = append(names, "content-type")
	}
	sort.Strings(names)
	headers := ""
	escape := func(v string) string { return strings.ReplaceAll(url.QueryEscape(v), "+", "%20") }
	for _, name := range names {
		value := req.Header.Get(name)
		if name == "host" {
			value = req.Host
		}
		if kind == "baidu" {
			headers += escape(name) + ":" + escape(value) + "\n"
		} else {
			headers += name + ":" + value + "\n"
		}
	}
	query := strings.ReplaceAll(req.URL.Query().Encode(), "+", "%20")
	uri := req.URL.EscapedPath()
	want := ""
	if kind == "huawei" {
		if !strings.HasSuffix(uri, "/") {
			uri += "/"
		}
		canonical := req.Method + "\n" + uri + "\n" + query + "\n" + headers + "\n" + strings.Join(names, ";") + "\n" + wireSHA(raw)
		want = "SDK-HMAC-SHA256 Access=" + cfg["AccessKeyId"] + ", SignedHeaders=" + strings.Join(names, ";") + ", Signature=" + hex.EncodeToString(wireHMAC("sha256", []byte(cfg["SecretAccessKey"]), "SDK-HMAC-SHA256\n"+date+"\n"+wireSHA([]byte(canonical))))
	} else {
		auth := "bce-auth-v1/" + cfg["AccessKeyId"] + "/" + date + "/1800"
		key := hex.EncodeToString(wireHMAC("sha256", []byte(cfg["SecretAccessKey"]), auth))
		canonical := req.Method + "\n" + uri + "\n" + query + "\n" + strings.TrimSuffix(headers, "\n")
		want = auth + "/" + strings.Join(names, ";") + "/" + hex.EncodeToString(wireHMAC("sha256", []byte(key), canonical))
	}
	if req.Header.Get("Authorization") != want {
		t.Error(kind + " canonical signature mismatch")
	}
}

func verifyWireAWS(t *testing.T, req *http.Request, raw []byte, cfg map[string]string, service, region string) {
	t.Helper()
	auth := req.Header.Get("Authorization")
	parts := strings.Split(auth, ", SignedHeaders=")
	if len(parts) != 2 {
		t.Fatal("AWS authorization missing")
	}
	tail := strings.Split(parts[1], ", Signature=")
	if len(tail) != 2 {
		t.Fatal("AWS signature missing")
	}
	names := strings.Split(tail[0], ";")
	headers := ""
	for _, name := range names {
		value := req.Header.Get(name)
		if name == "host" {
			value = req.Host
		}
		headers += name + ":" + strings.TrimSpace(value) + "\n"
	}
	query := req.URL.Query()
	keys := []string{}
	for name := range query {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	pairs := []string{}
	for _, name := range keys {
		sort.Strings(query[name])
		for _, value := range query[name] {
			pairs = append(pairs, strings.ReplaceAll(url.QueryEscape(name), "+", "%20")+"="+strings.ReplaceAll(url.QueryEscape(value), "+", "%20"))
		}
	}
	date := req.Header.Get("X-Amz-Date")
	scope := date[:8] + "/" + region + "/" + service + "/aws4_request"
	canonical := req.Method + "\n" + req.URL.EscapedPath() + "\n" + strings.Join(pairs, "&") + "\n" + headers + "\n" + tail[0] + "\n" + wireSHA(raw)
	k := wireHMAC("sha256", wireHMAC("sha256", wireHMAC("sha256", wireHMAC("sha256", []byte("AWS4"+cfg["SecretAccessKey"]), date[:8]), region), service), "aws4_request")
	want := hex.EncodeToString(wireHMAC("sha256", k, "AWS4-HMAC-SHA256\n"+date+"\n"+scope+"\n"+wireSHA([]byte(canonical))))
	if tail[1] != want || parts[0] != "AWS4-HMAC-SHA256 Credential="+cfg["AccessKeyId"]+"/"+scope || req.Header.Get("X-Amz-Content-Sha256") != wireSHA(raw) {
		t.Error("AWS canonical signature mismatch")
	}
}

func checkUniWireBusiness(t *testing.T, req *http.Request, raw []byte, target, method string, private *rsa.PrivateKey) {
	t.Helper()
	body := wireBody(t, req, raw)
	var biz map[string]any
	if json.Unmarshal([]byte(text(body["params"])), &biz) != nil {
		t.Fatal("uniCloud embedded business JSON invalid")
	}
	args := obj(biz["functionArgs"])
	got := text(args["method"])
	if got == "" {
		got = text(args["action"])
	}
	if text(biz["functionTarget"]) != target || got != method {
		t.Error("uniCloud business function mismatch")
	}
	var client map[string]any
	if json.Unmarshal([]byte(req.Header.Get("X-Client-Info")), &client) != nil || text(client["deviceId"]) == "" {
		t.Error("uniCloud client identity missing")
	}
	if private == nil {
		return
	}
	params := anyList(args["params"])
	if len(params) != 1 {
		t.Fatal("uniCloud login params missing")
	}
	envelope := obj(obj(params[0])["passwordEnvelope"])
	decode := func(name string) []byte {
		data, e := base64.StdEncoding.DecodeString(text(envelope[name]))
		if e != nil {
			t.Fatal(e)
		}
		return data
	}
	key, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, private, decode("encryptedKey"), nil)
	if e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		t.Fatal(e)
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	header := struct {
		Version     any `json:"version"`
		Algorithm   any `json:"algorithm"`
		KeyID       any `json:"keyId"`
		ChallengeID any `json:"challengeId"`
	}{envelope["version"], envelope["algorithm"], envelope["keyId"], envelope["challengeId"]}
	aad, _ := json.Marshal(header)
	encrypted := append(decode("ciphertext"), decode("tag")...)
	plain, e := gcm.Open(nil, decode("iv"), encrypted, aad)
	if e != nil {
		t.Fatal(e)
	}
	var payload map[string]any
	if json.Unmarshal(plain, &payload) != nil || text(payload["password"]) != "fixture-secret" || text(payload["email"]) != "fixture@example.com" || text(payload["challengeId"]) != "fixture-challenge" {
		t.Error("uniCloud encrypted login identity mismatch")
	}
	if text(body["timestamp"]) != strconv.FormatInt(1791853323000, 10) {
		t.Error("uniCloud timestamp mismatch")
	}
}
