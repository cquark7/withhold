//go:build !windows

package inspect

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenRegularRejectsSymlinkAndFIFOReplacements(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			name := filepath.Join(directory, "input")
			if err := os.WriteFile(name, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			expected, _ := os.Stat(name)
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if kind == "fifo" {
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				err = unix.Mkfifo(name, 0600)
			} else {
				if err := os.Rename(name, filepath.Join(directory, "original")); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink("original", name)
			}
			if err != nil {
				t.Fatal(err)
			}
			if f, err := openRegular(root, "input", expected); err == nil {
				_ = f.Close()
				t.Fatal("opened a replacement nonregular input")
			}
		})
	}
}
