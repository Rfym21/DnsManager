package cryptobox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dns-manager/dnsmgr/server/internal/privatefile"
)

type Box struct{ aead cipher.AEAD }

func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("master key must contain exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	return &Box{aead: aead}, err
}

// LoadOrCreate never replaces an existing key; the file must be included in backups.
func LoadOrCreate(filename string) (*Box, error) {
	f, err := os.Open(filename)
	if err == nil {
		defer f.Close()
		if e := privatefile.Validate(f); e != nil {
			return nil, fmt.Errorf("master key file must be private: %w", e)
		}
		b, e := io.ReadAll(f)
		if e != nil {
			return nil, errors.New("cannot read master key file")
		}
		key, e := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if e != nil {
			return nil, errors.New("invalid master key encoding")
		}
		return New(key)
	}
	if !os.IsNotExist(err) {
		return nil, errors.New("cannot read master key file")
	}
	if err = os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	f, err = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return LoadOrCreate(filename)
	}
	if err != nil {
		return nil, err
	}
	if err = privatefile.Restrict(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot protect master key file: %w", err)
	}
	if _, err = f.WriteString(base64.RawStdEncoding.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	return New(key)
}

func (b *Box) Seal(scope string, plaintext []byte) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, plaintext, []byte(scope))
	return "v1:" + base64.RawStdEncoding.EncodeToString(out), nil
}

func (b *Box) Open(scope, ciphertext string) ([]byte, error) {
	if !strings.HasPrefix(ciphertext, "v1:") {
		return nil, errors.New("unsupported secret version")
	}
	raw, err := base64.RawStdEncoding.DecodeString(ciphertext[3:])
	if err != nil || len(raw) < b.aead.NonceSize()+b.aead.Overhead() {
		return nil, errors.New("invalid encrypted secret")
	}
	return b.aead.Open(nil, raw[:b.aead.NonceSize()], raw[b.aead.NonceSize():], []byte(scope))
}

func RandomHex(size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
