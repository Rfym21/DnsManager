// Package contracts generates the public API specification and TypeScript
// models from the executable router, real Go response types and handler ASTs.
package contracts

import (
	"fmt"
	"sort"
	"strings"
)

type operationSpec struct {
	Summary      string
	Response     Schema
	Status       string
	Request      Schema
	BodyType     string
	Public       bool
	Authority    string
	Description  string
	ResponseType string
}

// Document builds a complete contract. An undocumented executable route is an
// error rather than silently receiving a generic placeholder schema.
func Document(root string) (map[string]any, error) {
	r := newRegistry()
	catalog(r)
	source, err := sources(root, r)
	if err != nil {
		return nil, err
	}
	routes, err := Routes()
	if err != nil {
		return nil, err
	}
	paths := map[string]any{}
	for _, route := range routes {
		spec, err := specification(route, r)
		if err != nil {
			return nil, err
		}
		origin := route.Handler
		switch origin {
		case "createRecord", "updateRecord":
			origin = "writeRecord"
		case "createObject", "updateObject":
			origin = "writeObject"
		}
		if spec.Status == "" {
			spec.Status = "200"
		}
		if spec.BodyType == "" {
			spec.BodyType = "application/json"
		}
		if spec.ResponseType == "" {
			spec.ResponseType = "application/json"
		}
		request := spec.Request
		if request == nil && route.Method != "GET" && route.Method != "HEAD" && route.Method != "DELETE" {
			request = source[origin].Request
		}
		if request != nil {
			request = refineRequest(origin, request)
			name := operationID(route) + "Request"
			r.Schemas[name] = request
			request = ref(name)
		}
		params := parameters(route, origin, source)
		security := []map[string][]string{}
		if !spec.Public {
			security = append(security, map[string][]string{"sessionCookie": {}}, map[string][]string{"bearerToken": {}})
			if spec.Authority == "personal" {
				security = security[:1]
			}
		}
		if spec.Authority == "legacy" {
			security = []map[string][]string{{"legacyDigest": {}}}
		}
		responses := map[string]any{spec.Status: map[string]any{"description": spec.Summary + "成功", "content": map[string]any{spec.ResponseType: map[string]any{"schema": spec.Response}}}}
		if route.Method == "HEAD" {
			responses[spec.Status] = map[string]any{"description": "数据库连接正常；HEAD 不返回响应体。"}
		}
		if route.Handler == "legacyQuicklogin" {
			responses[spec.Status] = map[string]any{"description": "单次票据兑换完成，设置会话 Cookie 并跳转 /domains。", "headers": map[string]any{"Location": map[string]any{"schema": scalar("string")}}}
		}
		errorsByStatus := map[string][]string{}
		if strings.HasPrefix(route.Path, "/api/v1") || route.Handler == "qqWebhook" {
			mergeErrors(errorsByStatus, source[origin].Errors)
			mergeErrors(errorsByStatus, map[string][]string{"500": {"internal_error"}, "404": {"not_found"}, "409": {"conflict"}})
			if request != nil {
				mergeErrors(errorsByStatus, map[string][]string{"400": {"invalid_json", "validation_failed"}})
			}
			if !spec.Public {
				mergeErrors(errorsByStatus, map[string][]string{"401": {"unauthorized"}, "403": {"forbidden"}})
			}
			if !spec.Public && route.Method != "GET" && route.Method != "HEAD" {
				mergeErrors(errorsByStatus, map[string][]string{"403": {"csrf_failed"}, "409": {"resource_busy"}})
			}
			if strings.Contains(route.Path, "records") || strings.Contains(route.Path, "cloudflare") || strings.Contains(route.Path, "provider") || strings.HasSuffix(route.Path, "verify") {
				mergeErrors(errorsByStatus, source["providerError"].Errors)
				mergeErrors(errorsByStatus, map[string][]string{"500": {"audit_failed_after_write"}})
			}
			for status, codes := range errorsByStatus {
				sort.Strings(codes)
				codes = unique(codes)
				responses[status] = map[string]any{"description": "可能的错误码: " + strings.Join(codes, ", ") + "。500 audit_failed_after_write 表示外部写入可能已经发生；先只读核对，勿直接重复写入。", "content": map[string]any{"application/json": map[string]any{"schema": ref("Error")}}, "x-error-codes": codes}
			}
			if route.Handler == "objectAction" {
				responses["200"] = map[string]any{"description": "pause/resume 返回 ResourceObject；preview 返回后续5次执行时刻；QQ bind 返回回调URL和绑定有效期。", "content": map[string]any{"application/json": map[string]any{"schema": Schema{"anyOf": []Schema{ref("ResourceObject"), list(ref("DateTime")), object(map[string]Schema{"url": scalar("string"), "until": ref("DateTime")}, "url", "until")}}}}}
			}
			if route.Handler == "legacyQQWebhook" {
				responses["200"] = map[string]any{"description": "op=13返回验证签名JSON；普通事件成功为空响应体。", "content": map[string]any{"application/json": map[string]any{"schema": spec.Response}, "text/plain": map[string]any{"schema": Schema{"type": "string", "const": ""}}}}
			}
		} else if strings.HasPrefix(route.Path, "/api/") {
			responses["200"].(map[string]any)["description"] = "兼容 PHP：业务错误通常仍返回 HTTP 200、code=-1、msg；查询成功形状见 schema。"
		} else if route.Handler != "healthLive" && route.Handler != "healthReady" && route.Handler != "qqWebhook" {
			for _, status := range []string{"400", "401", "403", "409", "503"} {
				responses[status] = map[string]any{"description": "旧回调/定时入口失败时返回文本；详情见该操作说明。", "content": map[string]any{"text/plain": map[string]any{"schema": scalar("string")}}}
			}
		}
		if route.Handler == "healthReady" {
			responses["503"] = map[string]any{"description": "数据库不可用。", "content": map[string]any{"application/json": map[string]any{"schema": ref("Error")}}}
		}
		op := map[string]any{"operationId": operationID(route), "summary": spec.Summary, "description": authorityDescription(spec.Authority) + spec.Description, "tags": []string{tag(route)}, "parameters": params, "security": security, "responses": responses, "x-go-handler": route.Handler, "x-chi-path": route.ChiPath, "x-authorization": spec.Authority}
		if request != nil {
			op["requestBody"] = map[string]any{"required": true, "content": map[string]any{spec.BodyType: map[string]any{"schema": request}}}
		}
		if spec.Authority == "legacy" {
			op["deprecated"] = true
		}
		item, ok := paths[route.Path].(map[string]any)
		if !ok {
			item = map[string]any{}
			paths[route.Path] = item
		}
		item[strings.ToLower(route.Method)] = op
	}
	return map[string]any{
		"openapi": "3.1.0", "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
		"info":    map[string]any{"title": "彩虹聚合 DNS 管理系统 Go API", "version": "1.0.0", "description": "由实际 chi Router、Go JSON 类型与 HTTP 请求结构生成。路径存在不代表生产云平台已验收；平台能力、权限和配置校验仍决定可执行操作。"},
		"servers": []map[string]string{{"url": "/", "description": "同源部署"}}, "paths": paths,
		"components": map[string]any{"schemas": r.Schemas, "securitySchemes": map[string]any{
			"sessionCookie": map[string]any{"type": "apiKey", "in": "cookie", "name": "dnsmgr_session", "description": "HttpOnly 会话；除 GET/HEAD 外需 X-CSRF-Token，并通过同源校验。"},
			"bearerToken":   map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "dm_…", "description": "个人 API 凭据，受 dns:read、dns:write、admin scope 和当前用户/域名授权共同限制。"},
			"legacyDigest":  map[string]any{"type": "http", "scheme": "legacy-md5", "description": "自定义旧认证，不使用 Authorization header；实际凭据在 application/x-www-form-urlencoded 的 uid、timestamp、sign，见 requestBody。MD5(key+timestamp+key)，时间窗 ±300 秒，未绑定 body、无 nonce，仅为旧客户端兼容。", "x-credential-location": "form"},
		}}, "x-route-count": len(routes),
	}, nil
}

func operationID(route Route) string {
	suffix := strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_").Replace(strings.Trim(route.Path, "/"))
	return strings.ToLower(route.Method) + "_" + suffix
}
func unique(values []string) []string {
	out := []string{}
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
func mergeErrors(dst, src map[string][]string) {
	for status, codes := range src {
		dst[status] = append(dst[status], codes...)
	}
}
func tag(route Route) string {
	if strings.Contains(route.Path, "cloudflare") {
		return "Cloudflare"
	}
	if strings.HasPrefix(route.Path, "/api/v1/") {
		parts := strings.Split(strings.TrimPrefix(route.Path, "/api/v1/"), "/")
		return parts[0]
	}
	if strings.HasPrefix(route.Path, "/health") {
		return "health"
	}
	return "legacy"
}
func authorityDescription(kind string) string {
	switch kind {
	case "admin":
		return "仅管理员；Bearer 还需 admin scope。域名独立会话无权限。Cookie 写入需 CSRF 和同源；写入受资源锁保护。"
	case "dns-read":
		return "需要目标域名 dns:read 授权及 Bearer dns:read scope；管理员、受限用户与独立域名会话均按当前权限核对。"
	case "dns-write":
		return "需要目标域名 dns:write 授权及 Bearer dns:write scope；独立域名会话可修改其授权域名。Cookie 写入需 CSRF/同源，远端写入受资源锁保护。"
	case "personal":
		return "仅普通用户 Cookie 会话；Bearer 与独立域名会话均禁止。写入需 CSRF/同源。"
	case "jobs-read":
		return "需 dns:read 或 admin scope；仅任务所有者或管理员，独立会话仅本域名。每个任务涉及的所有域名重新核对 dns:read；非 DNS 批次需管理员凭据。"
	case "jobs-write":
		return "读取任务权限基础上需 dns:write 或 admin scope；恢复动作再次核对全部域名写权限，非 DNS 批次需管理员。只有 failed/partial/unknown 可恢复，unknown 外部结果先核对。"
	case "audit":
		return "普通用户会话仅本人且当前授权域名的事件，管理员可读全部；Bearer 需 admin scope；独立域名会话禁止。"
	case "legacy":
		return "旧 uid/timestamp/sign POST 表单，按导入的旧身份和域名权限核对；证书导出需管理员。业务错误兼容 code=-1/msg。"
	case "qq":
		return "无需用户会话。QQ 通知渠道需启用；op=13 为平台验证挑战，普通事件需 X-Signature-Timestamp + X-Signature-Ed25519，允许过去5分钟、未来1分钟，签名覆盖 timestamp+原始body。"
	default:
		return ""
	}
}

func specification(route Route, r *registry) (operationSpec, error) {
	s := operationSpec{Authority: "admin"}
	s.Response = ref("OK")
	str, integer, boolean := scalar("string"), scalar("integer"), scalar("boolean")
	switch route.Handler {
	case "healthLive", "healthReady":
		s.Public = true
		s.Authority = "public"
		s.Summary = "服务健康检查"
		s.Response = object(map[string]Schema{"status": enumeration("ok")}, "status")
	case "setupStatus":
		s.Public = true
		s.Authority = "public"
		s.Summary = "查询安装与验证码状态"
		s.Response = object(map[string]Schema{"installed": boolean, "setup_token_required": boolean, "login_captcha": boolean}, "installed", "setup_token_required", "login_captcha")
	case "setup":
		s.Public = true
		s.Authority = "public"
		s.Summary = "创建初始管理员"
		s.Response = ref("Session")
		s.Description = "只能在未安装状态执行；配置 setup_token 或经回环地址访问；同源校验。用户名2–128字符，密码至少12字符、最多72字节。"
	case "login":
		s.Public = true
		s.Authority = "public"
		s.Summary = "账号登录"
		s.Response = ref("Session")
		s.Description = "同源请求；启用验证码时需 token/answer，启用 TOTP 时需 code。IP/用户名速率限制可能返回429。"
	case "captcha":
		s.Public = true
		s.Authority = "public"
		s.Summary = "获取登录验证码"
		s.Response = object(map[string]Schema{"token": str, "image": str, "expires_in": integer}, "token", "image", "expires_in")
		s.Description = "image 为 PNG data URL，有效期180秒。"
	case "domainLogin":
		s.Public = true
		s.Authority = "public"
		s.Summary = "兑换独立域名登录票据"
		s.Response = ref("Session")
		s.Description = "token 为64字符一次性票据，有效期5分钟；同源校验，复核票据签发人的当前写权限与域名登录开关。"
	case "me":
		s.Authority = "authenticated"
		s.Summary = "查询当前会话"
		s.Response = ref("Session")
		s.Description = "domain_id 非空即独立域名会话；/me 的 user 为实际签发账号，客户端不能仅由 user.role 判断域名会话。"
	case "logout":
		s.Authority = "authenticated"
		s.Summary = "退出当前会话"
	case "password":
		s.Authority = "personal"
		s.Summary = "修改密码"
		s.Description = "成功后全部现有会话失效，需要重新登录。"
	case "enrollTOTP":
		s.Authority = "personal"
		s.Summary = "开始 TOTP 绑定"
		s.Response = object(map[string]Schema{"secret": str, "otpauth_uri": str}, "secret", "otpauth_uri")
		s.Description = "需当前密码；待确认密钥有效10分钟，仅此端点返回待绑定 secret。"
	case "confirmTOTP":
		s.Authority = "personal"
		s.Summary = "确认 TOTP 绑定"
	case "disableTOTP":
		s.Authority = "personal"
		s.Summary = "关闭 TOTP"
		s.Description = "需当前密码与已启用 TOTP 动态码。"
	case "preferences":
		s.Authority = "personal"
		s.Summary = "保存个人界面偏好"
		s.Response = ref("Preferences")
	case "dashboard":
		s.Authority = "authenticated"
		s.Summary = "读取管理概览"
		s.Response = object(map[string]Schema{"domains": integer, "accounts": integer, "certificates": integer, "automations": integer, "pending_jobs": integer}, "domains", "accounts", "certificates", "automations", "pending_jobs")
	case "accounts":
		s.Summary = "读取 DNS 账户列表"
		s.Response = list(ref("Account"))
	case "accountDetail":
		s.Summary = "读取 DNS 账户配置"
		s.Response = ref("AccountDetail")
	case "addAccount":
		s.Summary = "新建 DNS 账户"
		s.Response = ref("Account")
		s.Status = "201"
	case "updateAccount":
		s.Summary = "修改 DNS 账户"
		s.Response = ref("Account")
		s.Description = "provider 不可变；config 非空值合并，空字符串保留原凭据。"
	case "deleteAccount":
		s.Summary = "删除 DNS 账户"
		s.Description = "有关联域名/任务时拒绝删除。"
	case "verifyAccount":
		s.Summary = "验证 DNS 账户连接"
	case "providerDomains":
		s.Summary = "读取平台域名列表"
		s.Response = paged(ref("ProviderDomain"))
	case "providers":
		s.Summary = "读取 DNS、签发与部署平台目录"
		s.Response = list(ref("Provider"))
		s.Description = "使用 category、fields、target_fields 与 capabilities 渲染动态表单；implemented 为实现声明，生产平台验收证据另见矩阵。"
	case "domains":
		s.Authority = "dns-read"
		s.Summary = "读取已授权域名"
		s.Response = list(ref("Domain"))
	case "domain":
		s.Authority = "dns-read"
		s.Summary = "读取域名详情"
		s.Response = ref("Domain")
	case "addDomain":
		s.Summary = "添加已有平台域名"
		s.Response = ref("Domain")
		s.Status = "201"
		s.Description = "需要 account_id、provider_domain_id、name，name 保留显示形式并转换为 ASCII/Punycode。"
	case "updateDomain":
		s.Summary = "修改域名显示与登录设置"
	case "deleteDomain":
		s.Summary = "移除管理域名"
		s.Description = "有关联资源时返回 conflict；不删除平台 Zone。"
	case "loginLink":
		s.Authority = "dns-write"
		s.Summary = "签发独立域名登录链接"
		s.Status = "201"
		s.Response = object(map[string]Schema{"token": str, "url": str, "expires_in": integer}, "token", "url", "expires_in")
		s.Description = "域名必须已启用 quicklogin；票据有效300秒、使用一次，token 放在 URL fragment。"
	case "domainDates":
		s.Authority = "dns-read"
		s.Summary = "读取注册与到期时间"
		s.Response = ref("DomainDates")
	case "saveDomainDates":
		s.Authority = "dns-write"
		s.Summary = "设置域名到期提醒"
		s.Description = "省略字段保持原值；空字符串清除日期；接受 YYYY-MM-DD 或 RFC3339。"
	case "refreshDomainDates":
		s.Authority = "dns-write"
		s.Summary = "从注册局刷新域名日期"
		s.Response = ref("RegistryDates")
	case "records":
		s.Authority = "dns-read"
		s.Summary = "读取 DNS 记录"
		s.Response = paged(ref("DNSRecord"))
		s.Response["properties"].(map[string]Schema)["capabilities"] = ref("DNSCapabilities")
		s.Response["properties"].(map[string]Schema)["fetched_at"] = ref("DateTime")
		s.Description = "记录 id 和 version 属于平台；保留 metadata 和多值记录信息。"
	case "recordDetail":
		s.Authority = "dns-read"
		s.Summary = "读取平台当前记录详情"
		s.Response = object(map[string]Schema{"record": ref("DNSRecord")}, "record")
	case "recordCheck":
		s.Authority = "dns-read"
		s.Summary = "检测记录公开DNS解析值"
		s.Response = ref("RecordCheckResult")
		s.Description = "服务端通过固定DoH resolver进行只读wire-format查询，不接受用户指定查询URL。matched表示全部期望Values在同name/type答案中；status active/mismatch/not_found/resolver_error。匹配不保证全球缓存已经刷新；DoH连接/响应失败返回502。"
	case "createRecord", "updateRecord":
		s.Authority = "dns-write"
		s.Summary = "写入 DNS 记录"
		s.Request = ref("DNSRecordWrite")
		s.Response = ref("DNSRecord")
		s.Description = "请求 TTL=0 自动设为1；所有字段按平台能力校验，更新建议提交读取到的 version 防止覆盖。"
	case "deleteRecord":
		s.Authority = "dns-write"
		s.Summary = "删除 DNS 记录"
	case "recordStatus":
		s.Authority = "dns-write"
		s.Summary = "切换 DNS 记录启用状态"
	case "recordRemark":
		s.Authority = "dns-write"
		s.Summary = "修改 DNS 记录备注"
	case "recordCapabilities":
		s.Authority = "dns-read"
		s.Summary = "读取域名能力、线路和最低 TTL"
		s.Response = object(map[string]Schema{"capabilities": ref("DNSCapabilities"), "lines": array(ref("DNSLine")), "min_ttl": integer}, "capabilities", "lines", "min_ttl")
		s.Response["properties"].(map[string]Schema)["proxy"] = boolean
		s.Response["required"] = []string{"capabilities", "lines", "min_ttl", "proxy"}
	case "recordGroups":
		s.Authority = "dns-read"
		s.Summary = "读取平台记录分组"
		s.Response = list(ref("DNSGroup"))
	case "setRecordGroup":
		s.Authority = "dns-write"
		s.Summary = "分配平台记录分组"
	case "recordLogs":
		s.Authority = "dns-read"
		s.Summary = "读取平台变更日志"
		s.Response = paged(ref("DNSLog"))
	case "recordWeights":
		s.Authority = "dns-read"
		s.Summary = "读取权重分组"
		s.Response = paged(ref("DNSWeightGroup"))
	case "setRecordWeight":
		s.Authority = "dns-write"
		s.Summary = "修改权重或权重组状态"
		s.Description = "enabled 非空时设置 name/type/line 分组状态；否则设置 record_id 对应的 weight。"
	case "providerAliases":
		s.Authority = "dns-read"
		s.Summary = "读取平台域名别名"
		s.Response = list(ref("DNSAlias"))
	case "writeProviderAlias":
		s.Authority = "dns-write"
		s.Summary = "创建或删除平台域名别名"
	case "recordBatch":
		s.Authority = "dns-write"
		s.Summary = "提交持久化 DNS 批次"
		s.Status = "202"
		s.Response = ref("QueuedJob")
		s.Description = "domain_ids × records 最多10000项；除 create 外必须一个域名且每项有平台记录ID。可带 Idempotency-Key（最多128字符），不同内容复用同一键返回409。成功项目在恢复时不重复执行。"
	case "recordImportPreview":
		s.Authority = "dns-read"
		s.Summary = "预览 Excel DNS 导入"
		s.BodyType = "multipart/form-data"
		s.Request = object(map[string]Schema{"domain_id": str, "file": Schema{"type": "string", "format": "binary"}}, "domain_id", "file")
		s.Response = ref("ImportPreview")
		s.Description = "只读：xls/xlsx ≤2MiB、5000行、64列；issues/warnings 包含源行号与线路回退说明。审核后另提交 record-batches。"
	case "jobs":
		s.Authority = "jobs-read"
		s.Summary = "读取最近100个可见任务"
		s.Response = list(ref("Job"))
	case "job", "reconcileJob":
		s.Authority = "jobs-read"
		s.Summary = "读取任务与逐项结果"
		s.Response = ref("JobDetail")
		if route.Handler == "reconcileJob" {
			s.Authority = "jobs-write"
			s.Summary = "只读核对任务未知结果"
			s.Description = "支持 record_batch/schedules/monitors/optimizations 的持久化 DNS 意图；唯一匹配才标记 succeeded，核对不执行平台写入。后三类需管理员和 admin scope。"
		}
	case "jobLogs":
		s.Authority = "jobs-read"
		s.Summary = "读取增量任务日志"
		s.Response = list(ref("JobEvent"))
	case "jobEvents":
		s.Authority = "jobs-read"
		s.Summary = "订阅任务 SSE 事件流"
		s.ResponseType = "text/event-stream"
		s.Response = described(str, "SSE: event=log 的 data 为 JobEvent；event=progress 的 data 为 Job；id 对应日志 ID；15秒注释心跳，Last-Event-ID 或 after 可恢复。")
		s.Description = "每秒复核当前身份、会话/Token及域名授权；撤权或任务终态关闭。反向代理需关闭缓冲。"
	case "cancelJob":
		s.Authority = "jobs-write"
		s.Summary = "请求取消任务"
		s.Description = "取消在安全边界生效；已完成的平台副作用不会回滚。"
	case "retryJob":
		s.Authority = "jobs-write"
		s.Summary = "恢复失败任务"
		s.Status = "202"
		s.Response = ref("QueuedJob")
		s.Description = "复用原任务意图与检查点，保留成功项；record_batch/schedules/monitors/optimizations 先只读核对持久化 DNS 项，unknown/running 未解决时拒绝重放，后三类需管理员。部署 unknown 不自动重放。"
	case "resolveDeploymentJob":
		s.Authority = "admin"
		s.Summary = "记录部署任务的外部人工核对结论"
		s.Response = ref("QueuedJob")
		s.Description = "仅 deployments 的 unknown/partial；reason 必填1–1000字，不得含PEM，实际凭据与证书材料存储前脱敏。核对结论只适用于原job提交marker和当前证书fingerprint；confirmed_success 标记succeeded，confirmed_no_write 标记failed后可retry；已有目标确认成功时拒绝无写入结论（409 partial_write_confirmed）。事务保存对象、任务、审计与事件，不发起供应商请求。"
	case "objects":
		s.Summary = "读取指定类型业务资源"
		s.Response = list(ref("ResourceObject"))
	case "object":
		s.Summary = "读取业务资源详情"
		s.Response = ref("ResourceObject")
	case "createObject", "updateObject":
		s.Summary = "保存业务资源配置"
		s.Response = ref("ResourceObject")
		s.Description = "data 按 kind 对应 Configuration schema；PATCH 使用当前 version 乐观锁。更新 domain_id 不改变归属，所有运行时状态由服务端保存。"
	case "deleteObject":
		s.Summary = "删除业务资源"
		s.Description = "有关联引用、待执行/未知任务时拒绝。"
	case "objectAction":
		s.Summary = "执行业务资源动作"
		s.Status = "202"
		s.Response = ref("QueuedJob")
		s.Description = "按 kind 校验动作：证书 execute/renew/revoke/cancel；部署 execute/test；监控 execute/test；计划 execute/preview；优选 execute/test/quota；账户/通知/委托/代理 test。pause/resume 返回200 ResourceObject；计划preview返回200 {items:DateTime[]}；QQ通知 bind 返回200 {url,until}，绑定窗口10分钟。quota创建202 Job，job.result为OptimizationQuota。"
		s.Response = Schema{"anyOf": []Schema{ref("QueuedJob"), ref("ResourceObject"), object(map[string]Schema{"url": str, "until": ref("DateTime")}, "url", "until")}}
	case "certificateImport":
		s.Summary = "导入 PEM 证书"
		s.Status = "201"
		s.Response = ref("ResourceObject")
		s.Description = "fullchain/private_key 必须匹配；解析 SAN、算法与有效期，导入证书不自动续期，普通响应私钥脱敏。"
	case "certificateDownload":
		s.Summary = "下载 PEM 或 PFX 证书"
		s.Response = object(map[string]Schema{"content": str, "filename": str, "base64": boolean}, "content", "filename", "base64")
		s.Description = "专用管理员出口返回证书/私钥；PFX content 为base64，PEM 为字符串。保存审计，未签发返回409。"
	case "users":
		s.Summary = "读取用户列表"
		s.Response = list(ref("User"))
	case "createUser":
		s.Summary = "创建用户"
		s.Status = "201"
		s.Response = ref("User")
	case "updateUser":
		s.Summary = "修改用户与启用状态"
		s.Description = "修改后用户全部会话失效；不能禁用/降级当前管理员或最后一个有效管理员。"
	case "deleteUser":
		s.Summary = "删除用户"
		s.Description = "不能删除当前或最后一个有效管理员。"
	case "grants":
		s.Summary = "读取用户域名授权"
		s.Response = list(ref("Grant"))
	case "setGrants":
		s.Summary = "替换用户域名授权"
		s.Description = "items 是完整目标授权集合；permissions 只允许 dns:read/dns:write；写权限包含读。"
	case "audit":
		s.Authority = "audit"
		s.Summary = "读取最近200条审计事件"
		s.Response = list(ref("AuditEvent"))
	case "settings":
		s.Summary = "读取可编辑系统设置"
		s.Response = ref("Settings")
	case "saveSettings":
		s.Summary = "原子保存可编辑系统设置"
		s.Description = "items 仅允许 site/network/deployment_security/security/retention；先验证整批再事务保存，内部签发与运行配置禁止此入口修改。"
	case "tokens":
		s.Authority = "personal"
		s.Summary = "读取本人 API 凭据"
		s.Response = list(ref("Token"))
	case "createToken":
		s.Authority = "personal"
		s.Summary = "创建个人 API 凭据"
		s.Status = "201"
		s.Response = object(map[string]Schema{"id": str, "token": str, "name": str}, "id", "token", "name")
		s.Description = "有效期1–365天，token 仅创建时展示；admin scope 仅管理员可授予。"
	case "deleteToken":
		s.Authority = "personal"
		s.Summary = "撤销本人 API 凭据"
	case "cfHostnames":
		s.Summary = "管理 Cloudflare for SaaS 主机名"
		s.Response = paged(ref("CloudflareHostname"))
		if route.Method == "POST" {
			s.Response = ref("CloudflareHostname")
			s.Status = "201"
		}
	case "cfHostname", "cfRefreshHostname":
		s.Summary = "读取或变更 Cloudflare 主机名"
		s.Response = ref("CloudflareHostname")
		s.Description = "hostname 路径参数是 Cloudflare ID；SSL更新合并现有设置；custom_origin_server null/空值清除。"
		if route.Method == "PATCH" {
			s.Request = object(map[string]Schema{"hostname": str, "ssl": ref("CloudflareSSL"), "custom_origin_server": nullable(str), "custom_metadata": dict(str)})
			s.Request["additionalProperties"] = ref("JSONValue")
		}
		if route.Method == "DELETE" {
			s.Response = object(map[string]Schema{"id": str})
		}
	case "cfHostnamesBatch":
		s.Summary = "批量管理 Cloudflare 主机名"
		s.Response = ref("CloudflareBatchResult")
		s.Description = "1–200项；action=add 使用 hostnames，update/delete 使用 ids。同步逐项执行，部分成功也返回200，读取 succeeded/failed。"
	case "cfHostnameTXT", "cfDCVDelegate":
		s.Summary = "写入 Cloudflare 验证 DNS 记录"
		s.Response = ref("CloudflareBatchResult")
		s.Description = "domain_id 为验证记录的目标管理域名，需要再次核对 dns:write；只创建或复用匹配的TXT/CNAME，逐项返回结果。"
	case "cfFallback":
		s.Summary = "管理 Cloudflare 回退源站"
		s.Response = ref("CloudflareFallback")
		s.Description = "不存在时 GET/DELETE 返回 {origin:\"\"}。"
	case "cfDCV":
		s.Summary = "读取 Cloudflare DCV UUID"
		s.Response = object(map[string]Schema{"uuid": str}, "uuid")
	case "cfTXTTargets":
		s.Summary = "选择验证记录目标域名"
		s.Response = list(ref("Domain"))
	case "cfTunnels":
		s.Summary = "管理 Cloudflare Tunnel"
		s.Response = list(ref("CloudflareTunnel"))
		if route.Method == "POST" {
			s.Response = ref("CloudflareTunnel")
			s.Status = "201"
		}
		s.Description = "需要 API Token 和明确 Account ID；创建时服务端生成32字节随机 tunnel_secret，默认 config_src=cloudflare。"
	case "cfTunnel":
		s.Summary = "删除 Tunnel 并清理自有 DNS"
		s.Response = object(map[string]Schema{"id": str})
		s.Description = "仅清理持久化凭据记录中本 Tunnel 创建且仍匹配的 DNS；清理中断后可重试。"
	case "cfTunnelToken":
		s.Summary = "读取 Tunnel 连接 Token"
		s.Response = object(map[string]Schema{"token": str}, "token")
	case "cfIngress":
		s.Summary = "读取或提交 Tunnel ingress"
		s.Response = ref("IngressResponse")
		s.Description = "写入需当前 version；ingress 最后一条必须是无 hostname 的兜底服务。sync_dns 默认 true，持久化前后配置/自有DNS凭据，部分失败可恢复。"
	case "cfTunnelRoutes":
		s.Summary = "管理 Tunnel CIDR 或主机名路由"
		s.Response = ref("CloudflareRoute")
		if route.Method == "GET" && !strings.Contains(route.Path, "{route}") {
			s.Response = list(ref("CloudflareRoute"))
		}
		s.Description = "routekind=cidr-routes 时 network 必须CIDR；hostname-routes 需有效hostname。GET/DELETE详情先确认 route 属于当前 Tunnel。"
	case "legacyDomains", "legacyDomainInfo", "legacyRecords", "legacyCertificate":
		s.Public = true
		s.Authority = "legacy"
		s.Summary = "旧客户端 API 兼容"
		s.BodyType = "application/x-www-form-urlencoded"
		s.Request = legacyRequest(route.Handler)
		s.Response = legacyResponse(route.Handler, r)
	case "legacyQuicklogin":
		s.Public = true
		s.Authority = "public"
		s.Summary = "兑换旧格式独立登录票据"
		s.Status = "302"
		s.Response = str
		s.Description = "domain/timestamp/token/sign 查询参数；保留旧 MD5 格式，只接受当前应用签发的一次性票据。"
	case "legacyHealth":
		s.Public = true
		s.Authority = "public"
		s.Summary = "旧运行状态检查"
		s.ResponseType = "text/plain"
		s.Response = enumeration("ok", "error")
	case "legacyCron":
		s.Public = true
		s.Authority = "public"
		s.Summary = "旧远程定时触发"
		s.ResponseType = "text/plain"
		s.Response = str
		s.Description = "key 查询参数，仅旧 cron_type=1且正确key时调度；返回 success!/未开启当前方式/访问密钥错误，任务副作用由worker执行。"
	case "legacyQQWebhook", "qqWebhook":
		s.Public = true
		s.Authority = "qq"
		s.Summary = "QQ 机器人平台回调"
		s.Request = qqRequest()
		s.Response = Schema{"anyOf": []Schema{ref("OK"), object(map[string]Schema{"plain_token": str, "signature": str}, "plain_token", "signature")}}
		s.Description = "新渠道专属URL /webhooks/qq/{id}；旧地址仅绑定具有当前库兼容映射的匹配渠道。旧事件成功响应可为空body。"
	default:
		return s, fmt.Errorf("missing concrete contract: %s %s (%s)", route.Method, route.Path, route.Handler)
	}
	return s, nil
}
