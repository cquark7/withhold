package session

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/certstore"
)

func TestMacRemovalRequiresVerifiedAbsence(t *testing.T) {
	for _, test := range []struct {
		name       string
		output     string
		probeError bool
		want       bool
	}{{"absent", "", false, true}, {"present", strings.Repeat("A", 40), false, false}, {"probe-failed", "", true, false}} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "login.keychain-db")
			_ = os.WriteFile(target, nil, 0600)
			fp := strings.Repeat("A", 40)
			_ = writeTrust(dir, TrustState{Fingerprint: fp, Platform: "darwin", Target: target, Installed: true})
			var calls [][]string
			adapter := Trust{Platform: "darwin", Home: dir, Run: func(name string, args ...string) ([]byte, error) {
				calls = append(calls, append([]string{name}, args...))
				if args[0] == "delete-certificate" {
					return nil, errors.New("delete failure can be harmless only after verified absence")
				}
				if test.probeError {
					return nil, errors.New("probe failed")
				}
				return []byte(test.output), nil
			}}
			err := adapter.Remove(dir)
			if (err == nil) != test.want {
				t.Fatalf("remove=%v", err)
			}
			if !reflect.DeepEqual(calls[0], []string{"security", "delete-certificate", "-Z", fp, "-t", target}) {
				t.Fatal(calls)
			}
			if exists(filepath.Join(dir, "trust-state.json")) == test.want {
				t.Fatal("metadata removal did not follow verification")
			}
		})
	}
}
func TestTrustInstallRetriesPartialAndRefusesDifferentCA(t *testing.T) {
	dir := t.TempDir()
	if err := certstore.Init(dir); err != nil {
		t.Fatal(err)
	}
	crt, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	fp := certFingerprint(crt)
	target := filepath.Join(dir, "login.keychain-db")
	_ = os.WriteFile(target, nil, 0600)
	_ = writeTrust(dir, TrustState{Fingerprint: fp, Platform: "darwin", Target: target})
	adds := 0
	adapter := Trust{Platform: "darwin", Home: dir, Run: func(_ string, args ...string) ([]byte, error) {
		if args[0] == "add-trusted-cert" {
			adds++
		}
		return []byte(fp), nil
	}}
	if err := adapter.Install(dir, false); err != nil {
		t.Fatal(err)
	}
	if adds != 1 {
		t.Fatal("partial install was skipped")
	}
	if err := adapter.Install(dir, false); err != nil || adds != 1 {
		t.Fatal("verified install was repeated")
	}
	_ = writeTrust(dir, TrustState{Fingerprint: strings.Repeat("F", 40), Platform: "darwin", Target: target, Installed: true})
	if adapter.Install(dir, false) == nil || adds != 1 {
		t.Fatal("different CA trust was overwritten")
	}
}
func TestNSSRemovalCannotDeleteAnotherCertificate(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, ".pki", "nssdb")
	_ = os.MkdirAll(db, 0700)
	_ = writeTrust(dir, TrustState{Fingerprint: strings.Repeat("A", 40), Platform: "linux", Target: "nss", Installed: true})
	deleted := false
	adapter := Trust{Platform: "linux", Home: dir, Run: func(_ string, args ...string) ([]byte, error) {
		for _, arg := range args {
			if arg == "-D" {
				deleted = true
			}
		}
		return []byte("different certificate"), nil
	}}
	if adapter.Remove(dir) == nil || deleted {
		t.Fatal("foreign NSS certificate deletion allowed")
	}
}
