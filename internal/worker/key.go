package worker

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/cquark7/withhold/internal/localstate"
)

// Resolve installation state at the worker boundary, not in the redactor.
// Publish the persisted placeholder key as a complete file for concurrent workers.
func placeholderKey() []byte {
	if env := os.Getenv("WITHHOLD_PLACEHOLDER_KEY"); env != "" {
		return []byte(env)
	}
	home, err := os.UserHomeDir()
	path := ""
	if err == nil {
		path = filepath.Join(home, ".config", "withhold", "placeholder-key")
	}
	read := func() []byte {
		data, err := localstate.ReadPrivate(path)
		if err != nil {
			return nil
		}
		return bytes.Trim(data, " \t\n\r\v\f")
	}
	if data := read(); len(data) > 0 {
		return data
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		panic("cannot initialize placeholder key")
	}
	key := []byte(hex.EncodeToString(random))
	if path != "" {
		if err := localstate.Write(path, append(key, '\n'), true); err == nil {
			return key
		}
		if data := read(); len(data) > 0 {
			key = data
		}
	}
	return key
}
