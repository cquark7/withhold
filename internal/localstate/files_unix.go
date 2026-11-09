//go:build !windows

package localstate

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func Protect(path string) error { return os.Chmod(path, 0600) }
func CheckPrivate(path string) error {
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || !ok || st.Uid != uint32(os.Geteuid()) {
		return errors.New("local state must be an owned private file (0600)")
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
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("another desktop command is running")
	}
	return func() { _ = f.Close() }, nil
}
