package contracts

import (
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/dns-manager/dnsmgr/server/internal/config"
	"github.com/dns-manager/dnsmgr/server/internal/httpapi"
	"github.com/go-chi/chi/v5"
)

type Route struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Handler string `json:"handler"`
	ChiPath string `json:"chi_path"`
}

// Routes walks the same chi router the server runs. Documentation does not have
// a second hand-maintained path registry. No requests or DB access occur here.
func Routes() ([]Route, error) {
	router := httpapi.New(nil, config.Config{}).Router
	out := []Route{}
	err := chi.Walk(router, func(method, path string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		name := runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name()
		if dot := strings.LastIndex(name, "."); dot >= 0 {
			name = name[dot+1:]
		}
		name = strings.TrimSuffix(name, "-fm")
		if path == "/health/live" {
			name = "healthLive"
		} else if path == "/health/ready" {
			name = "healthReady"
		}
		out = append(out, Route{Method: method, Path: normalizePath(path), Handler: name, ChiPath: path})
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Method < out[j].Method
		}
		return out[i].Path < out[j].Path
	})
	return out, err
}
func normalizePath(path string) string {
	start := strings.Index(path, "{")
	if start < 0 {
		return path
	}
	end := strings.Index(path[start:], "}")
	if end < 0 {
		return path
	}
	end += start
	parameter := path[start+1 : end]
	if colon := strings.Index(parameter, ":"); colon >= 0 {
		parameter = parameter[:colon]
	}
	return path[:start] + "{" + parameter + "}" + normalizePath(path[end+1:])
}
