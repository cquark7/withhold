package session

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cquark7/withhold/internal/localstate"
)

const nickname = "withhold-local-ca"

type TrustState struct {
	Fingerprint string `json:"fingerprint"`
	Platform    string `json:"platform"`
	Target      string `json:"target"`
	Installed   bool   `json:"installed"`
	Mode        string `json:"mode,omitempty"`
}
type Trust struct {
	Platform, Home string
	Run            func(string, ...string) ([]byte, error)
}

func SystemTrust() Trust {
	home, _ := os.UserHomeDir()
	return Trust{runtime.GOOS, home, func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}}
}
func certFingerprint(data []byte) string {
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
func readTrust(dir string) (TrustState, error) {
	var state TrustState
	data, err := os.ReadFile(filepath.Join(dir, "trust-state.json"))
	if err != nil {
		return state, err
	}
	if json.Unmarshal(data, &state) != nil || len(state.Fingerprint) != 40 {
		return state, errors.New("invalid trust metadata; preserving CA files")
	}
	return state, nil
}
func writeTrust(dir string, s TrustState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return localstate.Write(filepath.Join(dir, "trust-state.json"), data, false)
}
func (t Trust) databases() []string {
	return []string{filepath.Join(t.Home, ".local", "share", "pki", "nssdb"), filepath.Join(t.Home, ".pki", "nssdb")}
}
func (t Trust) macTarget(s TrustState) string {
	if s.Target != "" && s.Target != "nss" {
		return s.Target
	}
	return filepath.Join(t.Home, "Library", "Keychains", "login.keychain-db")
}
func (t Trust) Check(s TrustState, crt string) error {
	if s.Mode == "manual" {
		return nil
	}
	if s.Platform != t.Platform || !s.Installed {
		return errors.New("CA trust is incomplete; run withhold setup")
	}
	switch t.Platform {
	case "darwin":
		target := t.macTarget(s)
		if _, err := os.Stat(target); err != nil {
			return errors.New("recorded keychain is unavailable")
		}
		out, err := t.Run("security", "find-certificate", "-a", "-Z", target)
		if err != nil || !bytes.Contains(bytes.ToUpper(out), []byte(s.Fingerprint)) {
			return errors.New("CA is absent from the recorded keychain")
		}
		if _, err = t.Run("security", "verify-cert", "-c", crt, "-p", "basic", "-k", target); err != nil {
			return errors.New("CA trust verification failed")
		}
	case "linux":
		for _, db := range t.databases() {
			out, err := t.Run("certutil", "-d", "sql:"+db, "-L", "-n", nickname, "-a")
			if err != nil || certFingerprint(out) != s.Fingerprint {
				return errors.New("CA is absent or mismatched in an NSS database")
			}
		}
	default:
		return errors.New("automatic trust is unsupported; use manual trust")
	}
	return nil
}
func (t Trust) Install(dir string, manual bool) error {
	crt := filepath.Join(dir, "ca.crt")
	data, err := os.ReadFile(crt)
	if err != nil {
		return err
	}
	fp := certFingerprint(data)
	if fp == "" {
		return errors.New("cannot fingerprint CA")
	}
	s := TrustState{Fingerprint: fp, Platform: t.Platform, Installed: false}
	if previous, e := readTrust(dir); e == nil {
		if previous.Fingerprint != fp {
			return errors.New("recorded trust belongs to another CA; remove it before setup")
		}
		if previous.Mode != "manual" {
			s.Target = previous.Target
			if t.Check(previous, crt) == nil {
				return nil
			}
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if manual {
		s.Mode = "manual"
		return writeTrust(dir, s)
	}
	switch t.Platform {
	case "darwin":
		s.Target = t.macTarget(s)
		if _, err = os.Stat(s.Target); err != nil {
			return errors.New("login keychain is unavailable")
		}
		if err = writeTrust(dir, s); err != nil {
			return err
		}
		if _, err = t.Run("security", "add-trusted-cert", "-r", "trustRoot", "-k", s.Target, crt); err != nil {
			return errors.New("macOS trust installation failed")
		}
	case "linux":
		s.Target = "nss"
		if err = writeTrust(dir, s); err != nil {
			return err
		}
		for _, db := range t.databases() {
			if err = os.MkdirAll(db, 0700); err != nil {
				return err
			}
			if _, e := os.Stat(filepath.Join(db, "cert9.db")); os.IsNotExist(e) {
				if _, err = t.Run("certutil", "-d", "sql:"+db, "-N", "--empty-password"); err != nil {
					return errors.New("cannot initialize NSS database; install libnss3-tools")
				}
			}
			out, e := t.Run("certutil", "-d", "sql:"+db, "-L", "-n", nickname, "-a")
			if e == nil {
				if certFingerprint(out) != fp {
					return errors.New("NSS nickname belongs to a different certificate")
				}
				continue
			}
			if _, err = t.Run("certutil", "-d", "sql:"+db, "-A", "-t", "C,,", "-n", nickname, "-i", crt); err != nil {
				return errors.New("NSS trust installation failed")
			}
		}
	default:
		return fmt.Errorf("manual CA trust required: certutil -user -addstore Root %q; then withhold setup --trust manual", crt)
	}
	s.Installed = true
	if err = t.Check(s, crt); err != nil {
		return err
	}
	return writeTrust(dir, s)
}
func (t Trust) Remove(dir string) error {
	s, err := readTrust(dir)
	if err != nil {
		return errors.New("cannot verify trust removal without valid trust metadata")
	}
	if s.Platform != t.Platform {
		return errors.New("trust metadata belongs to a different platform")
	}
	if s.Mode == "manual" {
		return fmt.Errorf("remove CA %s from every manual trust store, then use withhold uninstall --keep-files; CA files are retained", s.Fingerprint)
	}
	switch t.Platform {
	case "darwin":
		target := t.macTarget(s)
		if _, err = os.Stat(target); err != nil {
			return errors.New("recorded keychain is unavailable; CA files retained")
		}
		_, _ = t.Run("security", "delete-certificate", "-Z", s.Fingerprint, "-t", target)
		out, e := t.Run("security", "find-certificate", "-a", "-Z", target)
		if e != nil || bytes.Contains(bytes.ToUpper(out), []byte(s.Fingerprint)) {
			return errors.New("cannot verify keychain removal; CA files retained")
		}
	case "linux":
		for _, db := range t.databases() {
			if _, e := os.Stat(db); os.IsNotExist(e) {
				continue
			} else if e != nil {
				return e
			}
			out, e := t.Run("certutil", "-d", "sql:"+db, "-L", "-n", nickname, "-a")
			if e == nil {
				if certFingerprint(out) != s.Fingerprint {
					return errors.New("NSS nickname changed; refusing to delete a different CA")
				}
				_, _ = t.Run("certutil", "-d", "sql:"+db, "-D", "-n", nickname)
			}
			out, e = t.Run("certutil", "-d", "sql:"+db, "-L")
			if e != nil || bytes.Contains(out, []byte(nickname)) {
				return errors.New("cannot verify NSS removal; CA files retained")
			}
		}
		// This adapter never installs into the root-owned system store.
		if data, e := os.ReadFile("/usr/local/share/ca-certificates/withhold-local-ca.crt"); e == nil && certFingerprint(data) == s.Fingerprint {
			return errors.New("remove the manually installed system CA and run update-ca-certificates before deleting local files")
		}
	default:
		return errors.New("automatic trust removal is unsupported; retain CA files")
	}
	return os.Remove(filepath.Join(dir, "trust-state.json"))
}
