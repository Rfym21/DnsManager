//go:build !windows

package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRejectsGroupAndOtherAccess(t *testing.T) {
	name := filepath.Join(t.TempDir(), "private.txt")
	if err := os.WriteFile(name, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0640, 0604, 0666} {
		if err := os.Chmod(name, mode); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		err = Validate(file)
		file.Close()
		if !errors.Is(err, ErrPermissions) {
			t.Fatalf("mode %04o: %v", mode, err)
		}
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("validation modified permissions")
		}
	}
}
