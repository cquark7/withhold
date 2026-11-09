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

func TestPrivateDACLRequiresProtectedCurrentUserPermissions(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for _, test := range []struct {
		name, descriptor string
		private          bool
	}{
		{"private", "D:P(A;;FA;;;" + sid + ")", true},
		{"owner and group metadata", "O:BAG:BAD:P(A;;FA;;;" + sid + ")", true},
		{"inheritance bookkeeping", "D:PAI(A;;FA;;;" + sid + ")", true},
		{"unprotected", "D:(A;;FA;;;" + sid + ")", false},
		{"shared", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)", false},
		{"other principal", "D:P(A;;FA;;;WD)", false},
		{"read only", "D:P(A;;FR;;;" + sid + ")", false},
		{"inheritable entry", "D:P(A;OI;FA;;;" + sid + ")", false},
		{"inherited entry", "D:P(A;ID;FA;;;" + sid + ")", false},
		{"empty", "D:P", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(test.descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if got := privateDACL(sd); got != test.private {
				t.Fatalf("private DACL: got %t, want %t", got, test.private)
			}
		})
	}
	t.Run("null DACL", func(t *testing.T) {
		sd, err := windows.NewSecurityDescriptor()
		if err != nil {
			t.Fatal(err)
		}
		if err = sd.SetDACL(nil, true, false); err != nil {
			t.Fatal(err)
		}
		if err = sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
			t.Fatal(err)
		}
		if privateDACL(sd) {
			t.Fatal("null DACL accepted as private")
		}
	})
}
