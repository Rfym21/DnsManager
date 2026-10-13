package database

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

// ErrBusy means another process currently holds a resource lock.
var ErrBusy = errors.New("resource is being modified")

// Lock serializes writers across processes without holding a SQL transaction.
// SQLite uses OS file locks; server databases use dedicated session locks.
func (d *DB) Lock(ctx context.Context, keys []string, timeout time.Duration) (func(), error) {
	keys = slices.Clone(keys)
	sort.Strings(keys)
	keys = slices.Compact(keys)
	if len(keys) == 0 {
		return func() {}, nil
	}
	var release func()
	var try func(string) (bool, error)
	if d.dialect == SQLite {
		held := []*flock.Flock{}
		release = func() {
			for _, l := range held {
				l.Unlock()
			}
		}
		try = func(key string) (bool, error) {
			sum := sha256.Sum256([]byte(key))
			l := flock.New(filepath.Join(d.lockDir, hex.EncodeToString(sum[:])+".lock"))
			ok, e := l.TryLock()
			if ok {
				held = append(held, l)
			}
			return ok, e
		}
	} else {
		conn, e := d.Conn(ctx)
		if e != nil {
			return nil, e
		}
		held := []string{}
		release = func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			failed := false
			for _, key := range held {
				var e error
				if d.dialect == MySQL {
					_, e = conn.ExecContext(cleanup, "SELECT RELEASE_LOCK(?)", key)
				} else {
					_, e = conn.ExecContext(cleanup, "SELECT pg_advisory_unlock(?)", lockNumber(key))
				}
				failed = failed || e != nil
			}
			// A lock release failure must discard the session rather than return
			// a still-locked connection to the reusable pool.
			if failed {
				_ = conn.Conn.Raw(func(any) error { return driver.ErrBadConn })
			}
			conn.Close()
		}
		try = func(key string) (bool, error) {
			sum := sha256.Sum256([]byte(d.name + "\x00" + key))
			name := "dnsmgr:" + hex.EncodeToString(sum[:24])
			if d.dialect == MySQL {
				name = "dnsmgr-write:" + hex.EncodeToString(sum[:24])
				switch key {
				case "@schema":
					schemaSum := sha256.Sum256([]byte(d.name))
					name = "dnsmgr-schema:" + hex.EncodeToString(schemaSum[:16])
				case "@install":
					name = "dnsmgr.install"
				}
			}
			var ok bool
			var e error
			if d.dialect == MySQL {
				var n int
				e = conn.QueryRowContext(ctx, "SELECT GET_LOCK(?,0)", name).Scan(&n)
				ok = n == 1
			} else {
				e = conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(?)", lockNumber(name)).Scan(&ok)
			}
			if ok {
				held = append(held, name)
			}
			return ok, e
		}
	}
	deadline := time.Now().Add(timeout)
	for _, key := range keys {
		for {
			if err := ctx.Err(); err != nil {
				release()
				return nil, err
			}
			ok, e := try(key)
			if e != nil {
				release()
				return nil, e
			}
			if ok {
				break
			}
			if timeout <= 0 || time.Now().After(deadline) {
				release()
				return nil, ErrBusy
			}
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				release()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}
	var once sync.Once
	return func() { once.Do(release) }, nil
}
func lockNumber(key string) int64 {
	sum := sha256.Sum256([]byte(key))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}
