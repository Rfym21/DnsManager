//go:build !windows

package cryptobox

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dns-manager/dnsmgr/server/internal/privatefile"
)

func TestLoadOrCreateRejectsReadableExistingKey(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "master.key")
	if _, err := LoadOrCreate(filename); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(filename); !errors.Is(err, privatefile.ErrPermissions) {
		t.Fatalf("readable key accepted: %v", err)
	}
	current, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(original, current) {
		t.Fatal("rejected key was modified")
	}
}
