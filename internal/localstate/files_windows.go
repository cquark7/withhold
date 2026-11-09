package localstate

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func privateSD() (*windows.SECURITY_DESCRIPTOR, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + u.User.Sid.String() + ")")
}
func Protect(path string) error {
	sd, err := privateSD()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
func CheckPrivate(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("local state must be a regular file")
	}
	actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	if !privateDACL(actual) {
		return errors.New("local state must have a protected current-user ACL")
	}
	return nil
}

func privateDACL(actual *windows.SECURITY_DESCRIPTOR) bool {
	control, _, err := actual.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	dacl, _, err := actual.DACL()
	if err != nil || dacl == nil {
		return false
	}
	// Compare the protected permission entries. Windows also records owner,
	// group, and inheritance bookkeeping in stored security descriptors.
	normalized, err := windows.NewSecurityDescriptor()
	if err != nil {
		return false
	}
	if err = normalized.SetDACL(dacl, true, false); err != nil {
		return false
	}
	if err = normalized.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return false
	}
	expected, err := privateSD()
	return err == nil && normalized.String() == expected.String()
}

func Lock(path string) (func(), error) {
	if err := Regular(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = Protect(path); err != nil {
		_ = f.Close()
		return nil, err
	}
	var overlapped windows.Overlapped
	if err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		_ = f.Close()
		return nil, errors.New("another desktop command is running")
	}
	return func() { _ = f.Close() }, nil
}
