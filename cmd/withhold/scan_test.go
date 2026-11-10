package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScanOptionsKeepPathsAndTextUnambiguous(t *testing.T) {
	for _, test := range []struct {
		args  []string
		paths []string
		text  string
		help  bool
		bad   bool
	}{
		{args: []string{"src", "--pii", "email", "config"}, paths: []string{"src", "config"}},
		{args: []string{"--text", "--help", "--pii=email"}, text: "--help"},
		{args: []string{"--", "--help", "-"}, paths: []string{"--help", "-"}},
		{args: []string{"src", "--help"}, help: true},
		{args: []string{"--pii"}, bad: true},
		{args: []string{"--secrets=invalid-private-value"}, bad: true},
		{args: []string{"--debug"}, bad: true},
	} {
		o := defaultOptions("~")
		paths, showHelp, err := parseScanOptions(o.flags("scan"), test.args)
		if (err != nil) != test.bad || showHelp != test.help || !reflect.DeepEqual(paths, test.paths) || o.text != test.text {
			t.Fatalf("args=%q paths=%q help=%t error=%v", test.args, paths, showHelp, err)
		}
	}
}

func TestScanConfigurationUsesDetectionPrecedenceWithoutEditorDiscovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("schema = 1\n[protection]\npii = [\"email\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WITHHOLD_PII", "phone")
	t.Setenv("WITHHOLD_INTEGRATION", "invalid")
	t.Setenv("WITHHOLD_EDITOR_SETTINGS_DIR", "nonexistent-editor")
	o := defaultOptions("~")
	f := o.flags("scan")
	if _, _, err := parseScanOptions(f, []string{"--config", path, "--pii", "us-ssn"}); err != nil {
		t.Fatal(err)
	}
	c, err := scanConfiguration(o, f)
	if err != nil || !reflect.DeepEqual(c.Protection.PII, []string{"us-ssn"}) {
		t.Fatalf("selection=%v error=%v", c.Protection.PII, err)
	}
	if err := os.WriteFile(path, []byte("schema = 1\nunknown = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanConfiguration(o, f); err == nil {
		t.Fatal("unknown configuration key was ignored")
	}
}
