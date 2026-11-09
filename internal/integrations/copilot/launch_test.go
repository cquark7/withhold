package copilot

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWindowsEditorShimUsesBundledCLIWithoutAShell(t *testing.T) {
	root := t.TempDir()
	shim := filepath.Join(root, "bin", "code.cmd")
	exe := filepath.Join(root, "Code.exe")
	cli := filepath.Join(root, "resources", "app", "out", "cli.js")
	if _, _, err := editorInvocation(shim, "windows"); err == nil {
		t.Fatal("incomplete editor accepted")
	}
	for _, file := range []string{shim, exe, cli} {
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary, args, err := editorInvocation(shim, "windows")
	if err != nil || binary != exe || !reflect.DeepEqual(args, []string{cli}) {
		t.Fatalf("invocation: %q %q %v", binary, args, err)
	}
	if binary, args, err = editorInvocation(exe, "windows"); err != nil || binary != exe || len(args) != 0 {
		t.Fatal("native executable changed")
	}
	if _, _, err := editorInvocation(filepath.Join(root, "bin", "unknown.cmd"), "windows"); err == nil {
		t.Fatal("arbitrary shell shim accepted")
	}
}
