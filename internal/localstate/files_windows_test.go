package localstate

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPrivateFilesRejectNonregularAndSharedWindowsACL(t *testing.T) {
	dir := t.TempDir()
	if CheckPrivate(dir) == nil {
		t.Fatal("directory accepted as private file")
	}
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("isolated fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Protect(path); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(path); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if CheckPrivate(path) == nil {
		t.Fatal("shared ACL accepted as private")
	}
}
