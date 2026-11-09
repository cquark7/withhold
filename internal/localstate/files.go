// Package localstate publishes complete local files without following symlinks.
package localstate

import (
	"errors"
	"os"
	"path/filepath"
)

func Regular(path string) error {
	s, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !s.Mode().IsRegular() {
		return errors.New("refusing a non-regular local file")
	}
	return nil
}

func Write(path string, data []byte, exclusive bool) error {
	if err := Regular(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".guard-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = Protect(f.Name()); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if exclusive {
		return os.Link(f.Name(), path)
	}
	return os.Rename(f.Name(), path)
}

func ReadPrivate(path string) ([]byte, error) {
	if err := Regular(path); err != nil {
		return nil, err
	}
	if err := CheckPrivate(path); err != nil {
		return nil, err
	}
	s, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if s.Size() > 1024*1024 {
		return nil, errors.New("local state file is too large")
	}
	return os.ReadFile(path)
}
