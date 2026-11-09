package session

import (
	"errors"
	"io"
	"os"
	"os/exec"
)

const startupReady = "\x01"

// LoadStartupRecord waits for the parent to finish publishing this child's PID
// before opening the private record. EOF without the signal aborts startup.
func LoadStartupRecord(path string, ready io.Reader) (Record, error) {
	var signal [1]byte
	if _, err := io.ReadFull(ready, signal[:]); err != nil || string(signal[:]) != startupReady {
		return Record{}, errors.New("session startup was not committed")
	}
	r, err := LoadRecord(path)
	if err != nil {
		return Record{}, err
	}
	if r.PID != os.Getpid() {
		return Record{}, errors.New("session record belongs to a different process")
	}
	return r, nil
}

func startSession(cmd *exec.Cmd, path string, record *Record) error {
	ready, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer ready.Close()
	if err = cmd.Start(); err != nil {
		return err
	}
	record.PID = cmd.Process.Pid
	// The child must not race a Windows file replacement or its ACL checks.
	// Release it only after the complete ownership record has been published.
	if err = saveRecord(path, *record); err == nil {
		_, err = io.WriteString(ready, startupReady)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	return err
}
