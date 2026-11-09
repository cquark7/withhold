package worker

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

// Resolve installation state at the worker boundary, not in the redactor.
// Publish the persisted placeholder key as a complete file for concurrent workers.
func placeholderKey() []byte {
	if env := os.Getenv("WITHHOLD_PLACEHOLDER_KEY"); env != "" {
		return []byte(env)
	}
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".config", "withhold", "placeholder-key")
	read := func() []byte { data, _ := os.ReadFile(path); return bytes.Trim(data, " \t\n\r\v\f") }
	if data := read(); len(data) > 0 {
		return data
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		panic("cannot initialize placeholder key")
	}
	key := []byte(hex.EncodeToString(random))
	if os.MkdirAll(filepath.Dir(path), 0700) == nil {
		file, err := os.CreateTemp(filepath.Dir(path), ".placeholder-key-*")
		if err == nil {
			name := file.Name()
			_, writeErr := file.Write(append(append([]byte(nil), key...), '\n'))
			closeErr := file.Close()
			if writeErr == nil && closeErr == nil {
				_ = os.Link(name, path)
			}
			_ = os.Remove(name)
		}
		if data := read(); len(data) > 0 {
			key = data
		}
	}
	return key
}
