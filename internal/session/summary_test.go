package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/control"
	"github.com/cquark7/withhold/internal/localstate"
)

func TestLastSessionSnapshotIsPrivateAndValueFree(t *testing.T) {
	dir := t.TempDir()
	if err := pendingSummary(dir); err != nil {
		t.Fatal(err)
	}
	c := config.Defaults("linux")
	c.Agents = []string{"cursor"}
	r := Record{Configuration: &c, Identity: control.Identity{Instance: "private-instance", Token: "private-token"}}
	live := &control.DebugStatus{Inspected: 3, Redacted: 2, Blocked: 1, BlockReasons: control.BlockReasons{Unsupported: 1}}
	summary := capturedSummary(r, live, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err := saveSummary(dir, summary); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, summaryName)
	if err := localstate.CheckPrivate(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(data), "private-") {
		t.Fatalf("summary included private identity: %s", data)
	}
	loaded, err := loadSummary(dir)
	if err != nil || !loaded.Available || loaded.Traffic.Inspected != 3 || loaded.Traffic.BlockReasons.Unsupported != 1 {
		t.Fatalf("summary not recovered: %+v, %v", loaded, err)
	}
	if err := pendingSummary(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err = loadSummary(dir)
	if err != nil || loaded.Available || loaded.Traffic != nil {
		t.Fatalf("old snapshot could be mistaken for a new session: %+v, %v", loaded, err)
	}
}

func TestLastSessionDoesNotOverwriteUnknownState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, summaryName)
	const original = `{"unrelated":"user data"}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pendingSummary(dir); err == nil {
		t.Fatal("unknown file was accepted as a session summary")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != original {
		t.Fatal("unknown file was overwritten")
	}
}
