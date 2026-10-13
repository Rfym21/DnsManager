package store

import (
	"context"
	"github.com/dns-manager/dnsmgr/server/internal/database"
)

var ErrResourceBusy = database.ErrBusy

// Resource locks serialize remote mutations across API and worker processes.
// They release when their connection or process exits, without holding SQL rows.
func (s *Store) LockResources(ctx context.Context, keys []string) (func(), error) {
	if len(keys) == 0 {
		return func() {}, nil
	}
	pool := s.LockDB
	if pool == nil {
		pool = s.DB
	}
	return pool.Lock(ctx, keys, 0)
}
