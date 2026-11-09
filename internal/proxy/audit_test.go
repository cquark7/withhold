package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cquark7/withhold/internal/localstate"
)

func TestAuditRotationBoundsDiskUseAndRetainsLatestRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := prepareAudit(path); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(10 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	appendFile(path, []byte("new record\n"))
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "new record\n" {
		t.Fatal("latest audit record was lost")
	}
	info, err := os.Stat(path + ".1")
	if err != nil || info.Size() != 10*1024*1024 {
		t.Fatal("previous audit file was not rotated")
	}
	for _, name := range []string{path, path + ".1"} {
		if err := localstate.CheckPrivate(name); err != nil {
			t.Fatalf("rotated file lost private permissions: %v", err)
		}
	}
}

func TestAuditDestinationsRefuseDirectories(t *testing.T) {
	if err := prepareAudit(t.TempDir()); err == nil {
		t.Fatal("directory accepted as audit output")
	}
	path := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(path+".1", 0700); err != nil {
		t.Fatal(err)
	}
	if err := prepareAudit(path); err == nil {
		t.Fatal("directory accepted as audit rotation backup")
	}
}

func TestAuditStartupProtectsExistingRotationBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit")
	if err := os.WriteFile(path+".1", []byte("previous records\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := prepareAudit(path); err != nil {
		t.Fatal(err)
	}
	if err := localstate.CheckPrivate(path + ".1"); err != nil {
		t.Fatal(err)
	}
}

func TestDebugLogCannotAliasAuditOrHintFilesOrBackups(t *testing.T) {
	for _, paths := range [][]string{
		{"debug", "debug", "hint"},
		{"debug", "audit", "debug.1"},
		{"audit", "audit.1", "hint"},
	} {
		if !logPathsCollide(paths[0], paths[1:]...) {
			t.Errorf("accepted colliding paths %q", paths)
		}
	}
	if logPathsCollide("state/debug", "state/audit", "state/hint") {
		t.Fatal("distinct logs treated as colliding")
	}
	dir := t.TempDir()
	debugPath := filepath.Join(dir, "debug")
	auditPath := filepath.Join(dir, "audit")
	if err := os.WriteFile(debugPath, []byte("sensitive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(debugPath, auditPath); err != nil {
		t.Fatal(err)
	}
	if !logPathsCollide(debugPath, auditPath) {
		t.Fatal("hard-linked debug and audit paths were accepted")
	}
}
