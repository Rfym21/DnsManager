package cryptobox

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateReopensTheSameKey(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "state", "master.key")
	first, err := LoadOrCreate(filename)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := first.Seal("fixture", []byte("round trip"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(filename)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := second.Open("fixture", ciphertext)
	if err != nil || string(plaintext) != "round trip" {
		t.Fatal("reopened master key did not decrypt the original value")
	}
	current, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(original, current) {
		t.Fatal("loading modified the master key file")
	}
}
