package worker

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPlaceholderKeyUsesCurrentOverrideAndPrivateFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("GUARD_PLACEHOLDER_PEPPER", "unused-alternate-prefix")
	t.Setenv("WITHHOLD_PLACEHOLDER_KEY", "")
	key := placeholderKey()
	if len(key) != 64 || string(key) == "unused-alternate-prefix" {
		t.Fatal("did not generate a private key")
	}
	path := filepath.Join(home, ".config", "withhold", "placeholder-key")
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(bytes.TrimSpace(data), key) || !bytes.Equal(placeholderKey(), key) {
		t.Fatal("key was not persisted and reused")
	}
	t.Setenv("WITHHOLD_PLACEHOLDER_KEY", "explicit-current-key")
	if string(placeholderKey()) != "explicit-current-key" {
		t.Fatal("current override did not take precedence")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("environment override changed the persisted key")
	}
}
