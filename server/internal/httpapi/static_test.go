package httpapi

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/dns-manager/dnsmgr/server/internal/config"
	"github.com/dns-manager/dnsmgr/server/internal/webui"
)

func TestEmbeddedFrontendRoutesWithoutDiskAssets(t *testing.T) {
	// Running outside the checkout proves no frontend directory is read at runtime.
	t.Chdir(t.TempDir())
	t.Setenv("WEB_DIR", t.TempDir())
	a := New(nil, config.Config{})
	index, err := fs.ReadFile(webui.Files(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(index, []byte(`id="root"`)) {
		t.Fatal("embedded frontend must contain the real React entry point")
	}
	for _, route := range []string{"/", "/index.html", "/login", "/domain-login?token=fixture", "/domains/fixture", "/objects/certificates", "/jobs/fixture", "/settings/"} {
		t.Run(route, func(t *testing.T) {
			w := httptest.NewRecorder()
			a.Router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, route, nil))
			if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), index) {
				t.Fatalf("route %s: status %d, embedded index mismatch", route, w.Code)
			}
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Cache-Control") != "no-cache" {
				t.Fatal("HTML must have its content type and require cache revalidation")
			}
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("static responses must retain security headers")
			}
		})
	}
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/login", nil))
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Length") != strconv.Itoa(len(index)) {
		t.Fatalf("HEAD route: %d, length %s, body %d", w.Code, w.Header().Get("Content-Length"), w.Body.Len())
	}
}

func TestEmbeddedFrontendAssets(t *testing.T) {
	t.Chdir(t.TempDir())
	a := New(nil, config.Config{})
	files := webui.Files()
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	links := regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`).FindAllSubmatch(index, -1)
	if len(links) < 2 {
		t.Fatal("embedded index must reference built JavaScript and CSS")
	}
	for _, link := range links {
		if _, err := fs.Stat(files, strings.TrimPrefix(string(link[1]), "/")); err != nil {
			t.Fatalf("index references missing embedded asset %s: %v", link[1], err)
		}
	}
	assetCount := 0
	err = fs.WalkDir(files, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasPrefix(name, "assets/") {
			return err
		}
		assetCount++
		content, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			a.Router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+name, nil))
			if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), content) {
				t.Fatalf("asset %s: %d, content mismatch", name, w.Code)
			}
			contentType := w.Header().Get("Content-Type")
			if path.Ext(name) == ".js" && !strings.Contains(contentType, "javascript") {
				t.Fatalf("JavaScript served as %s", contentType)
			}
			if path.Ext(name) == ".css" && !strings.HasPrefix(contentType, "text/css") {
				t.Fatalf("CSS served as %s", contentType)
			}
			if w.Header().Get("Location") != "" {
				t.Fatal("asset request must not redirect")
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if assetCount == 0 {
		t.Fatal("no frontend assets embedded")
	}
	assetPath := string(links[0][1])
	content, err := fs.ReadFile(files, strings.TrimPrefix(assetPath, "/"))
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, assetPath, nil)
		r.Header.Set("Range", "bytes=0-9")
		a.Router.ServeHTTP(w, r)
		if w.Code != http.StatusPartialContent || w.Header().Get("Content-Length") != "10" {
			t.Fatalf("%s asset range: %d, headers %v", method, w.Code, w.Header())
		}
		if method == http.MethodGet && !bytes.Equal(w.Body.Bytes(), content[:10]) || method == http.MethodHead && w.Body.Len() != 0 {
			t.Fatalf("%s asset range: incorrect body", method)
		}
	}
}

func TestEmbeddedFrontendRejectsMissingAssetsAndInvalidPaths(t *testing.T) {
	a := New(nil, config.Config{})
	for _, route := range []string{"/assets", "/assets/", "/assets/missing.js", "/assets/missing", "/missing.css", "/favicon.ico", "/../index.html", "/assets/%2e%2e/index.html", "/assets%5cindex.js", "/assets//index.js"} {
		t.Run(route, func(t *testing.T) {
			w := httptest.NewRecorder()
			a.Router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, route, nil))
			if w.Code != http.StatusNotFound || strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("invalid asset/path %s: %d, content type %s", route, w.Code, w.Header().Get("Content-Type"))
			}
		})
	}
	for _, route := range []string{"/api/v1/unknown", "/health", "/health/unknown"} {
		t.Run(route, func(t *testing.T) {
			w := httptest.NewRecorder()
			a.Router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, route, nil))
			if w.Code != http.StatusNotFound || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
				t.Fatalf("API/health miss %s: %d, content type %s", route, w.Code, w.Header().Get("Content-Type"))
			}
		})
	}
	// The legacy /api router retains its authentication before routing misses.
	for _, route := range []string{"/api", "/api/unknown"} {
		w := httptest.NewRecorder()
		a.Router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, route, nil))
		if w.Code != http.StatusForbidden || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("legacy API auth %s: %d, content type %s", route, w.Code, w.Header().Get("Content-Type"))
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		w := httptest.NewRecorder()
		a.Router.ServeHTTP(w, httptest.NewRequest(method, "/login", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s must not serve the frontend: %d", method, w.Code)
		}
	}
}
