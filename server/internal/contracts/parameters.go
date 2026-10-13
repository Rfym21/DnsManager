package contracts

import (
	"regexp"
	"sort"
	"strings"
)

func parameters(route Route, origin string, sources map[string]handlerSource) []map[string]any {
	params := []map[string]any{}
	for _, match := range regexp.MustCompile(`\{([^}:]+)(?::([^}]+))?\}`).FindAllStringSubmatch(route.ChiPath, -1) {
		name := match[1]
		schema := scalar("string")
		if len(match) > 2 && match[2] != "" {
			schema = enumeration(strings.Split(match[2], "|")...)
		}
		if name == "kind" {
			schema = enumeration(objectKinds...)
		}
		if name == "action" {
			schema = enumeration("execute", "renew", "revoke", "cancel", "test", "preview", "pause", "resume", "bind", "quota")
		}
		params = append(params, map[string]any{"in": "path", "name": name, "required": true, "schema": schema, "description": "资源标识；record/hostname/tunnel/route 使用平台ID，其他 id 使用 Go 资源ID。"})
	}
	queries := map[string]Schema{}
	for _, name := range sources[origin].Queries {
		queries[name] = scalar("string")
	}
	if origin == "records" || origin == "recordLogs" || origin == "recordWeights" {
		for _, name := range []string{"page", "page_size", "search", "name", "value", "type", "line", "enabled", "sort", "order", "group_id"} {
			queries[name] = scalar("string")
		}
	}
	if origin == "providerDomains" {
		for _, name := range []string{"page", "page_size", "search"} {
			queries[name] = scalar("string")
		}
	}
	if origin == "jobLogs" || origin == "jobEvents" {
		queries["after"] = Schema{"type": "integer", "minimum": 0}
	}
	if origin == "legacyQuicklogin" {
		for _, name := range []string{"domain", "timestamp", "token", "sign"} {
			queries[name] = scalar("string")
		}
	}
	if origin == "legacyCron" {
		queries["key"] = scalar("string")
	}
	names := []string{}
	for name := range queries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		schema := queries[name]
		if name == "page" {
			schema = Schema{"type": "integer", "minimum": 1, "default": 1}
		}
		if name == "page_size" {
			schema = Schema{"type": "integer", "minimum": 1, "maximum": 1000, "default": 50}
		}
		if name == "order" {
			schema = enumeration("asc", "desc")
		}
		params = append(params, map[string]any{"in": "query", "name": name, "required": origin == "legacyQuicklogin", "schema": schema})
	}
	if strings.HasPrefix(route.Path, "/api/v1/") && route.Method != "GET" && route.Method != "HEAD" {
		params = append(params, map[string]any{"in": "header", "name": "X-CSRF-Token", "required": false, "schema": scalar("string"), "description": "Cookie 会话必须提交 auth 响应中的 csrf_token；Bearer 不需要。"})
	}
	if origin == "recordBatch" || origin == "objectAction" {
		params = append(params, map[string]any{"in": "header", "name": "Idempotency-Key", "required": false, "schema": Schema{"type": "string", "maxLength": 128}, "description": "同用户+同键返回原任务，内容不同拒绝；执行动作支持，pause/resume/bind不创建任务。"})
	}
	if origin == "jobEvents" {
		params = append(params, map[string]any{"in": "header", "name": "Last-Event-ID", "required": false, "schema": scalar("string")})
	}
	if origin == "qqWebhook" || origin == "legacyQQWebhook" {
		for _, name := range []string{"X-Bot-Appid", "X-Signature-Timestamp", "X-Signature-Ed25519"} {
			params = append(params, map[string]any{"in": "header", "name": name, "required": false, "schema": scalar("string"), "description": "普通事件需签名；平台op=13挑战无需签名；Appid若存在必须匹配。"})
		}
	}
	return params
}

func refineRequest(handler string, schema Schema) Schema {
	props, ok := schema["properties"].(map[string]Schema)
	if !ok {
		return schema
	}
	if handler == "writeObject" {
		props["data"] = ref("ObjectConfiguration")
	}
	if handler == "saveSettings" {
		props["items"] = ref("SettingsItems")
	}
	if handler == "cfIngress" {
		props["config"] = ref("IngressConfig")
	}
	if handler == "cfHostnames" || handler == "cfHostnamesBatch" {
		props["ssl"] = nullable(ref("CloudflareSSL"))
	}
	if handler == "certificateDownload" {
		props["format"] = enumeration("pem", "crt", "fullchain", "key", "pfx")
	}
	if handler == "recordBatch" {
		props["operation"] = enumeration("create", "update", "delete", "enable", "disable", "remark")
	}
	if handler == "resolveDeploymentJob" {
		props["resolution"] = enumeration("confirmed_success", "confirmed_no_write")
		props["reason"] = Schema{"type": "string", "minLength": 1, "maxLength": 1000, "description": "外部核查依据；去首尾空白后必填，不能包含证书或私钥。"}
	}
	if handler == "createUser" || handler == "updateUser" {
		props["role"] = enumeration("admin", "restricted")
	}
	if handler == "preferences" {
		props["theme"] = enumeration("light", "dark", "system")
	}
	if handler == "createToken" {
		props["days"] = Schema{"type": "integer", "minimum": 1, "maximum": 365}
		props["scopes"] = nullable(array(enumeration("dns:read", "dns:write", "admin")))
	}
	if handler == "cfHostnamesBatch" {
		props["action"] = enumeration("add", "update", "delete")
	}
	if handler == "domainLogin" {
		props["token"] = Schema{"type": "string", "minLength": 64, "maxLength": 64}
	}
	for key, value := range props {
		if key == "password" || key == "current_password" || key == "private_key" || key == "setup_token" || key == "token" {
			value["writeOnly"] = true
		}
	}
	requirements := map[string][]string{
		"setup": {"username", "password"}, "login": {"username", "password"}, "domainLogin": {"token"},
		"password": {"current_password", "password"}, "enrollTOTP": {"password"}, "confirmTOTP": {"code"}, "disableTOTP": {"password"}, "preferences": {"theme"},
		"addAccount": {"name", "provider"}, "updateAccount": {"name"}, "addDomain": {"account_id", "provider_domain_id", "name"},
		"writeObject": {"name", "data"}, "recordBatch": {"domain_ids", "records", "operation"}, "certificateImport": {"fullchain", "private_key"}, "certificateDownload": {"format"},
		"createUser": {"username", "password", "role"}, "updateUser": {"username", "role", "enabled"}, "setGrants": {"items"}, "createToken": {"name", "days"}, "saveSettings": {"items"},
		"resolveDeploymentJob": {"resolution", "reason"},
		"cfHostnames":          {"hostname"}, "cfHostnamesBatch": {"action"}, "cfFallback": {"origin"}, "cfTunnels": {"name"}, "cfIngress": {"config"}, "cfHostnameTXT": {"domain_id"}, "cfDCVDelegate": {"domain_id", "hostnames"},
	}
	if names, ok := requirements[handler]; ok {
		schema["required"] = names
	}
	return schema
}

func qqRequest() Schema {
	return object(map[string]Schema{"op": scalar("integer"), "t": scalar("string"), "id": scalar("string"), "d": object(map[string]Schema{"event_ts": scalar("string"), "plain_token": scalar("string"), "id": scalar("string"), "author": object(map[string]Schema{"user_openid": scalar("string")})})}, "op", "d")
}
func legacyRequest(handler string) Schema {
	props := map[string]Schema{"uid": scalar("string"), "timestamp": scalar("string"), "sign": scalar("string")}
	fields := map[string][]string{
		"legacyDomains":    {"id", "aid", "type", "kw", "offset", "limit", "sort", "order"},
		"legacyDomainInfo": {"loginurl"}, "legacyCertificate": {"id"},
		"legacyRecords": {"recordid", "name", "type", "value", "line", "ttl", "mx", "weight", "remark", "status", "keyword", "subdomain", "offset", "limit", "sortName", "sortOrder", "recordinfo", "action", "groupid"},
	}
	for _, name := range fields[handler] {
		props[name] = scalar("string")
	}
	if handler == "legacyRecords" {
		props["recordinfo"] = described(scalar("string"), "JSON字符串数组，每项{RecordId:string}，最多1000项；batch action=open/pause/delete/remark/group。")
	}
	return object(props, "uid", "timestamp", "sign")
}
func legacyResponse(handler string, r *registry) Schema {
	str := scalar("string")
	integer := scalar("integer")
	failed := object(map[string]Schema{"code": integer, "msg": str}, "code", "msg")
	domain := object(map[string]Schema{"id": str, "aid": str, "name": str, "thirdid": str, "type": str, "typename": str, "aremark": str, "remark": str, "category_name": str, "is_hide": integer, "is_sso": integer, "addtime": str})
	if _, ok := r.Schemas["LegacyDomain"]; !ok {
		r.Schemas["LegacyDomain"] = domain
	}
	switch handler {
	case "legacyDomains":
		return Schema{"anyOf": []Schema{object(map[string]Schema{"total": integer, "rows": array(ref("LegacyDomain"))}, "total", "rows"), failed}}
	case "legacyDomainInfo":
		props := domain["properties"].(map[string]Schema)
		props["config"] = object(map[string]Schema{"type": str, "name": str, "status": scalar("boolean"), "remark": integer, "page": scalar("boolean"), "sort": scalar("boolean"), "weight": scalar("boolean"), "add": scalar("boolean"), "redirect": scalar("boolean"), "log": scalar("boolean")})
		props["recordLine"] = array(ref("DNSLine"))
		props["minTTL"] = integer
		props["loginurl"] = str
		return Schema{"anyOf": []Schema{object(map[string]Schema{"code": integer, "data": domain}, "code", "data"), failed}}
	case "legacyRecords":
		record := object(map[string]Schema{"RecordId": str, "Name": str, "Type": str, "Value": Schema{"anyOf": []Schema{str, array(str)}}, "Line": str, "LineName": str, "TTL": integer, "MX": nullable(integer), "Status": enumeration("0", "1"), "Weight": nullable(integer), "Remark": str, "UpdateTime": ref("JSONValue")})
		return Schema{"anyOf": []Schema{object(map[string]Schema{"total": integer, "rows": array(record)}, "total", "rows"), array(record), failed}}
	case "legacyCertificate":
		return Schema{"anyOf": []Schema{object(map[string]Schema{"code": integer, "data": object(map[string]Schema{"id": str, "crt": str, "key": str, "pfx": str, "issuetime": str, "expiretime": str, "domains": array(str)}, "id", "crt", "key", "pfx", "issuetime", "expiretime", "domains")}, "code", "data"), failed}}
	}
	return failed
}
