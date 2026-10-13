package deploy

import "testing"

func appendSessionWireCases(t *testing.T, cases *[]deployWireCase, chain, key string) {
	t.Helper()
	add := func(kind string, cfg, target map[string]string, steps ...deployWireStep) {
		*cases = append(*cases, deployWireCase{kind: kind, cfg: cfg, target: target, steps: steps})
	}
	loginPage := wireStep("GET", "/login", `<input name="_csrf_token" value="fixture-csrf">`)
	login := wireStep("POST", "/login", "")
	login.status = 302
	login.responseHeaders = map[string]string{"Location": "/dashboard", "Set-Cookie": "fixture=session; Path=/; Secure; HttpOnly"}
	login.fields = map[string]string{"userName": "fixture-user", "password": "fixture-secret", "_csrf_token": "fixture-csrf"}
	getImport := wireStep("GET", "/site/example.com/certificate/import", `<input name="site_import_certificate[_token]" value="fixture-import">`)
	getImport.headers = map[string]string{"Cookie": "fixture=session"}
	putImport := wireWrite("POST", "/site/example.com/certificate/import", "", map[string]string{"site_import_certificate[privateKey]": key, "site_import_certificate[certificate]": chain, "site_import_certificate[_token]": "fixture-import"})
	putImport.status = 302
	putImport.responseHeaders = map[string]string{"Location": "/site/example.com/certificates"}
	putImport.headers = map[string]string{"Cookie": "fixture=session"}
	add("cloudpanel", map[string]string{"username": "fixture-user", "password": "fixture-secret"}, map[string]string{"sites": "example.com"}, loginPage, login, getImport, putImport)
	amhLogin := wireStep("POST", "/", "")
	amhLogin.query = map[string]string{"c": "amapi", "a": "login"}
	amhLogin.status = 302
	amhLogin.responseHeaders = map[string]string{"Location": "/?amh_token=fixture-token"}
	amhInstall := wireWrite("POST", "/", `<div id="success">安装成功</div>`, map[string]string{"key_content1": key, "crt_content1": chain, "amh_token": "fixture-token"})
	amhInstall.query = map[string]string{"c": "amssl", "a": "admin_amssl", "envs_name": "fixture-env", "vhost_name": "example.com"}
	add("amh", map[string]string{"apikey": "fixture-secret"}, map[string]string{"env_name": "fixture-env", "vhost_name": "example.com"}, amhLogin, amhInstall)
	for _, kind := range []string{"kangle", "kangleadmin"} {
		cfg := map[string]string{"username": "fixture-user", "password": "fixture-secret", "skey": "fixture-secret"}
		target := map[string]string{"type": "1", "domains": "example.com", "name": "fixture-site"}
		steps := []deployWireStep{}
		if kind == "kangle" {
			s := wireStep("POST", "/vhost/index.php", "")
			s.query = map[string]string{"c": "session", "a": "login"}
			s.fields = map[string]string{"username": "fixture-user", "passwd": "fixture-secret"}
			s.status = 302
			s.responseHeaders = map[string]string{"Location": "/vhost/", "Set-Cookie": "fixture=session; Path=/; Secure"}
			steps = append(steps, s)
		} else {
			s := wireStep("GET", "/admin/index.php", "")
			s.query = map[string]string{"c": "sso", "a": "hello"}
			s.status = 302
			s.responseHeaders = map[string]string{"Location": "/admin/index.php?r=fixture-session", "Set-Cookie": "fixture=session; Path=/; Secure"}
			steps = append(steps, s)
			s = wireStep("GET", "/admin/index.php", "")
			s.query = map[string]string{"c": "sso", "a": "login", "name": "fixture-user", "r": "fixture-session", "s": wireMD5("fixture-sessionfixture-userfixture-sessionfixture-secret")}
			s.status = 302
			s.responseHeaders = map[string]string{"Location": "/admin/"}
			steps = append(steps, s)
			s = wireStep("GET", "/admin/index.php", "")
			s.query = map[string]string{"c": "vhost", "a": "impLogin", "name": "fixture-site"}
			s.status = 302
			s.responseHeaders = map[string]string{"Location": "/vhost/"}
			steps = append(steps, s)
		}
		steps = append(steps, wireStep("GET", "/vhost/", ""))
		s := wireWrite("POST", "/vhost/", "配置成功", map[string]string{"certificate": chain, "certificate_key": key, "domain": "example.com"})
		s.query = map[string]string{"c": "ssl", "a": "domainSsl"}
		s.headers = map[string]string{"Cookie": "fixture=session"}
		steps = append(steps, s)
		add(kind, cfg, target, steps...)
	}
	upLogin := wireStep("POST", "/accounts/signin/", `{"data":{"result":true}}`)
	upLogin.fields = map[string]string{"username": "fixture-user", "password": "fixture-secret"}
	upLogin.responseHeaders = map[string]string{"Set-Cookie": "fixture=session; Path=/; Secure"}
	upUpload := wireWrite("POST", "/api/https/certificate/", `{"data":{"status":0,"result":{"certificate_id":"9"}}}`, map[string]string{"certificate": chain})
	upUpload.headers = map[string]string{"Cookie": "fixture=session"}
	upSearch := wireStep("GET", "/api/https/certificate/search", `{"data":{"result":{"old":{"commonName":"example.com","config_domain":true}}}}`)
	upSearch.query = map[string]string{"limit": "100", "domain": "example.com"}
	upMigrate := wireStep("POST", "/api/https/migrate/certificate", `{"data":{"result":true}}`)
	upMigrate.fields = map[string]string{"new_crt_id": "9", "old_crt_id": "old"}
	add("upyun", map[string]string{"username": "fixture-user", "password": "fixture-secret"}, map[string]string{}, upLogin, upUpload, upSearch, upMigrate)
	synoLogin := wireStep("POST", "/webapi/entry.cgi", `{"success":true,"data":{"sid":"fixture-session","synotoken":"fixture-token"}}`)
	synoLogin.fields = map[string]string{"api": "SYNO.API.Auth", "version": "6", "method": "login", "account": "fixture-user", "passwd": "fixture-secret"}
	synoList := wireStep("GET", "/webapi/entry.cgi", `{"success":true,"data":{"certificates":[{"id":"9","subject":{"common_name":"example.com"}}]}}`)
	synoList.query = map[string]string{"api": "SYNO.Core.Certificate.CRT", "method": "list", "_sid": "fixture-session", "SynoToken": "fixture-token"}
	synoImport := wireWrite("POST", "/webapi/entry.cgi", `{"success":true}`, map[string]string{"id": "9", "desc": "fixture-cert", "key": key, "cert": chain})
	synoImport.query = map[string]string{"api": "SYNO.Core.Certificate", "method": "import", "_sid": "fixture-session", "SynoToken": "fixture-token"}
	add("synology", map[string]string{"username": "fixture-user", "password": "fixture-secret"}, map[string]string{"desc": "fixture-cert"}, synoLogin, synoList, synoImport)
	npmLogin := wireStep("POST", "/api/tokens", `{"token":"fixture-token"}`)
	npmLogin.fields = map[string]string{"identity": "fixture@example.com", "secret": "fixture-secret"}
	npmGet := wireStep("GET", "/api/nginx/certificates/9", `{"id":9,"provider":"other"}`)
	npmUpload := wireWrite("POST", "/api/nginx/certificates/9/upload", `{}`, map[string]string{"certificate": chain, "certificate_key": key})
	add("nginxproxymanager", map[string]string{"email": "fixture@example.com", "password": "fixture-secret"}, map[string]string{"id": "9"}, npmLogin, npmGet, npmUpload)
	qLogin := wireStep("GET", "/login", `<script src="/fixture.js"></script>`)
	qScript := wireStep("GET", "/fixture.js", `createServerReference)("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",1,"login")createServerReference)("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",1,"updateCertificateAction")`)
	qPost := wireStep("POST", "/login", `1:{"success":true}`)
	qPost.fields = map[string]string{"1_email": "fixture@example.com", "1_password": "fixture-secret"}
	qPost.headers = map[string]string{"next-action": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Accept": "text/x-component", "next-router-state-tree": qzyunRouterState}
	qPost.responseHeaders = map[string]string{"Set-Cookie": "fixture=session; Path=/; Secure"}
	qCert := wireStep("GET", "/certificate", `<script src="/fixture.js"></script>`)
	qUpdate := wireWrite("POST", "/certificate", `1:{"success":true}`, map[string]string{"1_certDocumentId": "123456789012345678901234", "1_serverCertificate": chain, "1_privateKey": key})
	qUpdate.headers = map[string]string{"next-action": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "Cookie": "fixture=session", "Accept": "text/x-component", "next-router-state-tree": qzyunRouterState}
	add("qzyun", map[string]string{"email": "fixture@example.com", "password": "fixture-secret"}, map[string]string{"certificate": "123456789012345678901234"}, qLogin, qScript, qPost, qCert, qScript, qUpdate)
}
