package httpapi

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/webui"
)

func (a *API) static(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/health" || strings.HasPrefix(r.URL.Path, "/health/") {
		a.fail(w, r, http.StatusNotFound, "not_found", "接口不存在")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if name == "" {
		name = "index.html"
	}
	if !fs.ValidPath(name) || strings.ContainsAny(name, "\\\x00") {
		http.NotFound(w, r)
		return
	}
	content, err := fs.ReadFile(webui.Files(), name)
	if err != nil {
		// Missing assets must remain 404s, rather than returning HTML as JS/CSS.
		if name == "assets" || strings.HasPrefix(name, "assets/") || path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		// React owns extensionless application routes, including deep links.
		name = "index.html"
		content, err = fs.ReadFile(webui.Files(), name)
		if err != nil {
			a.fail(w, r, http.StatusInternalServerError, "frontend_unavailable", "前端资源不可用")
			return
		}
	}
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(content))
}
