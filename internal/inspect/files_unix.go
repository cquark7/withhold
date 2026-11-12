//go:build !windows

package inspect

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openRead(root *os.Root, name string) (*os.File, error) {
	// Nonblocking open prevents a regular-file-to-FIFO race from hanging intake.
	// Root resolves parent directories safely, but follows final symlinks even
	// when OpenFile is given O_NOFOLLOW. Open the final component ourselves.
	directory, err := root.OpenFile(filepath.Dir(name), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), filepath.Base(name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func IsTerminal(f *os.File) bool {
	_, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	return err == nil
}
