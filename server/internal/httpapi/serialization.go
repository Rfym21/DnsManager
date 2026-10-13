package httpapi

import (
	"errors"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/go-chi/chi/v5"
	"net/http"
	"strings"
)

func (a *API) serializeMutation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "HEAD" {
			next.ServeHTTP(w, r)
			return
		}
		keys := []string{}
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
		id := chi.URLParam(r, "id")
		if strings.HasPrefix(path, "objects/") || strings.HasPrefix(path, "domains") || strings.HasPrefix(path, "accounts") || path == "record-batches" {
			keys = append(keys, "resource-catalog")
		}
		switch {
		case strings.HasPrefix(path, "domains/"):
			if strings.HasSuffix(path, "/dates") || strings.HasSuffix(path, "/dates/refresh") {
				keys = append(keys, "domain-expiry:"+id)
			}
			if d, err := a.Store.Domain(r.Context(), id); err == nil {
				keys = append(keys, "dns-account:"+d.AccountID)
			}
		case strings.HasPrefix(path, "accounts/"):
			keys = append(keys, "dns-account:"+id)
		case strings.HasPrefix(path, "objects/") && id != "":
			keys = append(keys, "object:"+id)
		}
		release, err := a.Store.LockResources(r.Context(), keys)
		if errors.Is(err, store.ErrResourceBusy) {
			a.fail(w, r, 409, "resource_busy", "该资源正在执行变更，请稍后重试")
			return
		}
		if err != nil {
			a.internal(w, r, err)
			return
		}
		defer release()
		// Persist intent before invoking a writer, so deletes and failed remote
		// acknowledgments leave an audit record.
		if path != "auth/logout" && !strings.HasSuffix(path, "/download") && !strings.HasSuffix(path, "/preview") && path != "record-imports/preview" {
			if err = a.Store.Audit(r.Context(), principal(r).User.ID, "request.mutation", "request", path, "", "", map[string]string{"method": r.Method}); err != nil {
				a.internal(w, r, err)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
