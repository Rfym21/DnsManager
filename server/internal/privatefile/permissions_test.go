package privatefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestrictedFileRemainsPrivateAfterReopen(t *testing.T) {
	name := filepath.Join(t.TempDir(), "private.txt")
	file, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := Restrict(file); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err := file.WriteString("fixture"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, err = os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := Validate(file); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateFileRequiresRegularFile(t *testing.T) {
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := Validate(file); err == nil {
		t.Fatal("directory accepted as private file")
	}
	if err := Restrict(file); err == nil {
		t.Fatal("directory permissions changed as private file")
	}
}
