package localstate

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
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
	expected, err := privateSD()
	if err != nil {
		return err
	}
	actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	// Accept only the protected current-user ACL created by this runtime.
	if actual.String() != expected.String() {
		return errors.New("local state must have a protected current-user ACL")
	}
	return nil
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
