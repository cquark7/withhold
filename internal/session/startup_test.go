package session

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/control"
)

func startupRecord(t *testing.T) Record {
	t.Helper()
	c := config.Defaults("fixture", runtime.GOOS)
	return Record{Schema: 1, Identity: control.Identity{Instance: control.Random(), Token: control.Random()}, PID: os.Getpid(), Port: c.Proxy.Port, Resource: filepath.Join(t.TempDir(), "client.ini"), Integration: c.Integration, Configuration: &c}
}

type observedStartupReader struct {
	io.Reader
	started chan struct{}
}

func (r observedStartupReader) Read(p []byte) (int, error) {
	select {
	case r.started <- struct{}{}:
	default:
	}
	return r.Reader.Read(p)
}

func TestStartupRecordWaitsUntilPublicationCompletes(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateName)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	started := make(chan struct{}, 1)
	type result struct {
		record Record
		err    error
	}
	done := make(chan result, 1)
	go func() {
		r, err := LoadStartupRecord(path, observedStartupReader{reader, started})
		done <- result{r, err}
	}()
	select {
	case <-started:
	case <-done:
		t.Fatal("child opened the missing record before waiting for publication")
	case <-time.After(5 * time.Second):
		t.Fatal("child did not wait for the startup signal")
	}
	select {
	case <-done:
		t.Fatal("child did not wait for the startup signal")
	default:
	}
	// The record is deliberately absent until the child's readiness read begins.
	// This models a file replacement that has not finished on Windows.
	want := startupRecord(t)
	if err := saveRecord(path, want); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, startupReady); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.record.PID != want.PID || got.record.Identity != want.Identity {
			t.Fatal("child did not load the committed ownership record")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child did not load the published record")
	}
}

func TestStartupRecordRejectsUncommittedAndForeignOwnership(t *testing.T) {
	for _, test := range []struct {
		name, signal string
		pid          int
		valid        bool
	}{
		{"committed", startupReady, os.Getpid(), true},
		{"parent closed before commit", "", os.Getpid(), false},
		{"invalid startup signal", "\x02", os.Getpid(), false},
		{"pending PID", startupReady, 0, false},
		{"different PID", startupReady, os.Getpid() + 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), StateName)
			r := startupRecord(t)
			r.PID = test.pid
			if err := saveRecord(path, r); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadStartupRecord(path, strings.NewReader(test.signal)); (err == nil) != test.valid {
				t.Fatalf("unexpected startup record validity: %v", err)
			}
		})
	}
}

func TestStartupSignalDoesNotBypassPrivateRecordValidation(t *testing.T) {
	for _, state := range []string{"missing", "directory", "invalid JSON", "inconsistent configuration"} {
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), StateName)
			switch state {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "invalid JSON", "inconsistent configuration":
				r := startupRecord(t)
				r.Configuration.Proxy.Port++
				if err := saveRecord(path, r); err != nil {
					t.Fatal(err)
				}
				if state == "invalid JSON" {
					if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := LoadStartupRecord(path, strings.NewReader(startupReady)); err == nil {
				t.Fatal("invalid private record accepted after startup signal")
			}
		})
	}
}

func TestFailedPublicationKillsAndReapsUnreleasedChild(t *testing.T) {
	path := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "_session-serve", "--state", path)
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	r := startupRecord(t)
	if err := startSession(cmd, path, &r); err == nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("non-regular ownership destination accepted")
	}
	if cmd.Process == nil || cmd.ProcessState == nil {
		t.Fatal("publication failure did not reap the child")
	}
	if strings.Contains(log.String(), "session record committed before child read") {
		t.Fatal("child was released despite failed record publication")
	}
}
