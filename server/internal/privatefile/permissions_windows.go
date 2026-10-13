package privatefile

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func currentUser() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

func privileged(sid, user *windows.SID) bool {
	return sid != nil && (sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

// Restrict installs a protected DACL allowing only the current account, SYSTEM
// and Administrators. Call it before writing a newly created private file.
func Restrict(file *os.File) error {
	if err := regular(file); err != nil {
		return err
	}
	user, err := currentUser()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(file.Name(), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return err
	}
	// Verify the opened object as well as the path used to install its ACL.
	return Validate(file)
}

// Validate checks the opened object's owner and DACL; it does not change them.
// DOS file mode bits do not describe Windows account access.
func Validate(file *os.File) error {
	if err := regular(file); err != nil {
		return err
	}
	user, err := currentUser()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if !privileged(owner, user) {
		return ErrPermissions
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil {
		return ErrPermissions
	}
	const privateAccess = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.MAXIMUM_ALLOWED
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if ace.Mask&privateAccess != 0 && !privileged(sid, user) {
				return ErrPermissions
			}
		default:
			// Object and callback ACE layouts require additional access evaluation;
			// do not assume an unfamiliar grant is private.
			return fmt.Errorf("%w: unsupported ACL entry", ErrPermissions)
		}
	}
	runtime.KeepAlive(descriptor)
	return nil
}
