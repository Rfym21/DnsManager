//go:build !windows

package privatefile

import "os"

// Restrict limits an opened file to its owner's read and write access.
// Call it before writing private contents into a newly created file.
func Restrict(file *os.File) error {
	if err := regular(file); err != nil {
		return err
	}
	return file.Chmod(0600)
}

// Validate rejects group or other access without modifying existing permissions.
func Validate(file *os.File) error {
	if err := regular(file); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return ErrPermissions
	}
	return nil
}
