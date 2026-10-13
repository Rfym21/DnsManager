// Package privatefile applies and checks private file permissions on each platform.
package privatefile

import (
	"errors"
	"os"
)

// ErrPermissions means another unprivileged account can access a private file.
var ErrPermissions = errors.New("private file permissions allow access by other accounts")

func regular(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("private file must be a regular file")
	}
	return nil
}
