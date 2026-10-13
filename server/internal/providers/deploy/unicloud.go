package deploy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type unicloudProvider struct {
	*httpProvider
	device string
}

func (p *unicloudProvider) clientInfo(name string) map[string]any {
	return map[string]any{"PLATFORM": "web", "OS": "windows", "APPID": "__UNI__unicloud_console", "DEVICEID": p.device, "scene": 1001, "appId": "__UNI__unicloud_console", "appLanguage": "zh-Hans", "appName": name, "appVersion": "1.0.0", "appVersionCode": "100", "browserName": "chrome", "browserVersion": "132.0.0.0", "deviceId": p.device, "deviceModel": "PC", "deviceType": "pc", "hostName": "chrome", "hostVersion": "132.0.0.0", "osName": "windows", "osVersion": "10 x64", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36", "uniCompilerVersion": "5.23", "uniPlatform": "web", "uniRuntimeVersion": "5.23", "locale": "zh-Hans", "LOCALE": "zh-Hans"}
}
func (p *unicloudProvider) invoke(ctx context.Context, endpoint, space, signKey string, biz map[string]any, info map[string]any, token string) (map[string]any, error) {
	q := *p.httpProvider
	if p.cfg["url"] == "" {
		q.base = endpoint
	}
	raw, e := json.Marshal(biz)
	if e != nil {
		return nil, e
	}
	body := map[string]any{"method": "serverless.function.runtime.invoke", "params": string(raw), "spaceId": space, "timestamp": p.opts.Now().UnixMilli()}
	keys := []string{}
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{}
	for _, k := range keys {
		value := text(body[k])
		if n, ok := body[k].(int64); ok {
			value = strconv.FormatInt(n, 10)
		}
		parts = append(parts, k+"="+value)
	}
	mac := hmac.New(md5.New, []byte(signKey))
	mac.Write([]byte(strings.Join(parts, "&")))
	client, _ := json.Marshal(info)
	headers := map[string]string{"Origin": "https://account.dcloud.net.cn", "Referer": "https://account.dcloud.net.cn/", "X-Client-Info": string(client), "X-Serverless-Sign": hex.EncodeToString(mac.Sum(nil))}
	if token != "" {
		headers["X-Client-Token"] = token
	}
	v, e := q.json(ctx, http.MethodPost, "/client", body, headers)
	if e != nil {
		return nil, e
	}
	if !truth(obj(v)["success"]) {
		return nil, errors.New(safeError(v, p.cfg))
	}
	return obj(obj(v)["data"]), nil
}
func (p *unicloudProvider) envelope(data map[string]any) (map[string]any, error) {
	if text(data["algorithm"]) != "RSA-OAEP-256+A256GCM" {
		return nil, errors.New("unsupported uniCloud password encryption algorithm")
	}
	block, _ := pem.Decode([]byte(text(data["publicKey"])))
	if block == nil {
		return nil, errors.New("uniCloud password encryption public key unavailable")
	}
	pub, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok || rsaKey.N.BitLen() < 2048 {
		return nil, errors.New("uniCloud requires RSA-2048 or stronger password encryption key")
	}
	key := make([]byte, 32)
	iv := make([]byte, 12)
	if _, e = rand.Read(key); e != nil {
		return nil, e
	}
	if _, e = rand.Read(iv); e != nil {
		return nil, e
	}
	header := struct {
		Version     any `json:"version"`
		Algorithm   any `json:"algorithm"`
		KeyID       any `json:"keyId"`
		ChallengeID any `json:"challengeId"`
	}{data["version"], data["algorithm"], data["keyId"], data["challengeId"]}
	aad, e := json.Marshal(header)
	if e != nil {
		return nil, e
	}
	payload := struct {
		Action      string `json:"action"`
		ChallengeID any    `json:"challengeId"`
		IssuedAt    int64  `json:"issuedAt"`
		Password    string `json:"password"`
		Email       string `json:"email"`
	}{"login", data["challengeId"], p.opts.Now().UnixMilli(), p.cfg["password"], p.cfg["username"]}
	plaintext, e := json.Marshal(payload)
	if e != nil {
		return nil, e
	}
	aesCipher, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	gcm, e := cipher.NewGCM(aesCipher)
	if e != nil {
		return nil, e
	}
	encrypted := gcm.Seal(nil, iv, plaintext, aad)
	encryptedKey, e := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, key, nil)
	if e != nil {
		return nil, e
	}
	return map[string]any{"version": data["version"], "algorithm": data["algorithm"], "keyId": data["keyId"], "challengeId": data["challengeId"], "encryptedKey": base64.StdEncoding.EncodeToString(encryptedKey), "iv": base64.StdEncoding.EncodeToString(iv), "ciphertext": base64.StdEncoding.EncodeToString(encrypted[:len(encrypted)-gcm.Overhead()]), "tag": base64.StdEncoding.EncodeToString(encrypted[len(encrypted)-gcm.Overhead():])}, nil
}
func (p *unicloudProvider) login(ctx context.Context) (string, error) {
	if p.cfg["username"] == "" || p.cfg["password"] == "" {
		return "", errors.New("uniCloud username and password are required")
	}
	info := p.clientInfo("账号中心")
	biz := func(method string, params map[string]any) map[string]any {
		return map[string]any{"functionTarget": "uni-id-co", "functionArgs": map[string]any{"method": method, "params": []any{params}, "clientInfo": info}}
	}
	key, e := p.invoke(ctx, "https://account.dcloud.net.cn", "uni-id-server", "ba461799-fde8-429f-8cc4-4b6d306e2339", biz("createPasswordChallenge", map[string]any{"action": "login", "resetAppId": "__UNI__unicloud_console", "resetUniPlatform": "web"}), info, "")
	if e != nil {
		return "", e
	}
	envelope, e := p.envelope(key)
	if e != nil {
		return "", e
	}
	data, e := p.invoke(ctx, "https://account.dcloud.net.cn", "uni-id-server", "ba461799-fde8-429f-8cc4-4b6d306e2339", biz("login", map[string]any{"captcha": "", "resetAppId": "__UNI__unicloud_console", "resetUniPlatform": "web", "isReturnToken": false, "passwordEnvelope": envelope}), info, "")
	if e != nil {
		return "", e
	}
	if text(data["errCode"]) != "0" {
		return "", errors.New(safeError(map[string]any{"msg": data["errMsg"]}, p.cfg))
	}
	token := text(obj(data["newToken"])["token"])
	if token == "" {
		return "", errors.New("uniCloud login token unavailable")
	}
	return token, nil
}
func (p *unicloudProvider) Validate(ctx context.Context) error { _, e := p.login(ctx); return e }
func (p *unicloudProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if _, _, _, e := parsePair(chain, key); e != nil {
		return info, e
	}
	if target.Config["spaceId"] == "" {
		return info, errors.New("uniCloud space ID is required")
	}
	provider := target.Config["provider"]
	if provider != "aliyun" && provider != "tencent" && provider != "alipay" {
		return info, errors.New("invalid uniCloud provider")
	}
	token, e := p.login(ctx)
	if e != nil {
		return info, e
	}
	client := p.clientInfo("uniCloud控制台")
	data, e := p.invoke(ctx, "https://unicloud.dcloud.net.cn", "dc-6nfabcn6ada8d3dd", "4c1f7fbf-c732-42b0-ab10-4634a8bbe834", map[string]any{"functionTarget": "uni-cloud-kernel", "functionArgs": map[string]any{"action": "user/getUserToken", "data": map[string]any{"isLogin": true}, "clientInfo": client, "uniIdToken": token}}, client, token)
	if e != nil {
		return info, e
	}
	inner := obj(data["data"])
	if text(data["code"]) != "0" || text(inner["ret"]) != "0" {
		return info, errors.New("uniCloud host token request failed")
	}
	hostToken := text(obj(inner["data"])["token"])
	if hostToken == "" {
		return info, errors.New("uniCloud host token unavailable")
	}
	q := *p.httpProvider
	if p.cfg["url"] == "" {
		q.base = "https://unicloud-api.dcloud.net.cn"
	}
	return batch(ctx, splitLines(strings.ReplaceAll(target.Config["domains"], ",", "\n")), info, func(domain string) error {
		v, e := q.json(ctx, http.MethodPost, "/unicloud/api/host/create-domain-with-cert", map[string]string{"appid": "", "provider": provider, "spaceId": target.Config["spaceId"], "domain": domain, "cert": strings.ReplaceAll(url.QueryEscape(chain), "+", "%20"), "key": strings.ReplaceAll(url.QueryEscape(key), "+", "%20")}, map[string]string{"Token": hostToken})
		if e != nil {
			return e
		}
		if text(obj(v)["ret"]) != "0" {
			return errors.New(safeError(map[string]any{"msg": obj(v)["desc"]}, p.cfg))
		}
		return nil
	})
}
