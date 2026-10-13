package cryptobox

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dns-manager/dnsmgr/server/internal/privatefile"
	"golang.org/x/sys/windows"
)

func TestLoadOrCreateRejectsBroadExistingACLWithoutChangingKey(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "master.key")
	if _, err := LoadOrCreate(filename); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetNamedSecurityInfo(filename, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	runtime.KeepAlive(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(filename); !errors.Is(err, privatefile.ErrPermissions) {
		t.Fatalf("broad master key ACL accepted: %v", err)
	}
	current, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(original, current) {
		t.Fatal("rejected master key was modified")
	}
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := privatefile.Validate(file); !errors.Is(err, privatefile.ErrPermissions) {
		t.Fatal("key ACL was changed during rejection")
	}
}
