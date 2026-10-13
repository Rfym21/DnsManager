package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func setTestDACL(t *testing.T, name, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	runtime.KeepAlive(descriptor)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsOtherAccountAndNullDACL(t *testing.T) {
	name := filepath.Join(t.TempDir(), "private.txt")
	file, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := Restrict(file); err != nil {
		t.Fatal(err)
	}
	user, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	setTestDACL(t, name, "D:P(A;;FA;;;"+user.String()+")(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)")
	if err := Validate(file); !errors.Is(err, ErrPermissions) {
		t.Fatalf("Everyone read access accepted: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := Validate(file); !errors.Is(err, ErrPermissions) {
		t.Fatalf("NULL DACL accepted: %v", err)
	}
	if err := Restrict(file); err != nil {
		t.Fatal(err)
	}
}
