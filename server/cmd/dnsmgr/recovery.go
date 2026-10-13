package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/dns-manager/dnsmgr/server/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Recovery requires filesystem/database access. Passwords are read from a file,
// never command arguments (which are visible in process listings).
func recoverUser(ctx context.Context, s *store.Store, args []string) error {
	if len(args) != 2 || (args[0] != "password" && args[0] != "totp") {
		return errors.New("usage: dnsmgr recover password|totp USERNAME; password requires RECOVERY_PASSWORD_FILE")
	}
	u, err := s.UserByName(ctx, args[1])
	if err != nil {
		return errors.New("recovery user not found")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if args[0] == "password" {
		filename := os.Getenv("RECOVERY_PASSWORD_FILE")
		if filename == "" {
			return errors.New("RECOVERY_PASSWORD_FILE is required")
		}
		info, err := os.Stat(filename)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("recovery password must be a private regular file (0600)")
		}
		raw, err := os.ReadFile(filename)
		if err != nil {
			return errors.New("cannot read recovery password file")
		}
		password := strings.TrimRight(string(raw), "\r\n")
		if utf8.RuneCountInString(password) < 12 || len(password) > 72 {
			return errors.New("password must contain at least 12 characters and at most 72 bytes")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE users SET password_hash=?,updated_at=UTC_TIMESTAMP(6) WHERE id=?", hash, u.ID)
		if err != nil {
			return err
		}
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE users SET totp_enabled=FALSE,totp_secret=NULL,updated_at=UTC_TIMESTAMP(6) WHERE id=?", u.ID)
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=?", u.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM api_tokens WHERE user_id=?", u.ID); err != nil {
		return err
	}
	detail, _ := json.Marshal(map[string]string{"method": args[0]})
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_events(actor_id,action,resource_type,resource_id,request_id,detail,created_at) VALUES (?,'identity.recover','user',?,'local-cli',?,UTC_TIMESTAMP(6))", u.ID, u.ID, detail); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	fmt.Println("Recovery completed; browser sessions and API tokens revoked.")
	return nil
}
