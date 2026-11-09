package certstore

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestCAKeepsExistingFilesAndSignsVerifiedLeaves(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if Init(dir) == nil {
		t.Fatal("existing CA was overwritten")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
	if string(before) != string(after) {
		t.Fatal("key changed")
	}
	ca, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	for _, host := range []string{"api.githubcopilot.com", "127.0.0.1", "::1"} {
		leaf, err := ca.Leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(leaf.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, CurrentTime: time.Now()}); err != nil {
			t.Fatal(err)
		}
		again, _ := ca.Leaf(host)
		if leaf != again {
			t.Fatal("leaf cache missed")
		}
	}
	if runtime.GOOS != "windows" {
		if os.Chmod(filepath.Join(dir, "ca.key"), 0644) != nil {
			t.Fatal("chmod")
		}
		if _, err = Load(dir); err == nil {
			t.Fatal("public private key accepted")
		}
	}
}

func TestConcurrentInitPublishesOneCompletePair(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for range 8 {
		wg.Go(func() {
			if Init(dir) == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("created %d pairs", success)
	}
	if _, err := Load(dir); err != nil {
		t.Fatal(err)
	}
}

func TestPartialCAIsRefusedWithoutModification(t *testing.T) {
	for _, name := range []string{"ca.key", "ca.crt"} {
		dir := t.TempDir()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("partial"), 0600); err != nil {
			t.Fatal(err)
		}
		if Init(dir) == nil {
			t.Fatal("partial CA accepted")
		}
		if _, err := Load(dir); err == nil {
			t.Fatal("partial CA loaded")
		}
		data, _ := os.ReadFile(path)
		if string(data) != "partial" {
			t.Fatal("existing data changed")
		}
	}
}

func TestCALoadRefusesNonregularFiles(t *testing.T) {
	for _, name := range []string{"ca.key", "ca.crt"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := Init(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			if err := os.Rename(path, path+".original"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(dir); err == nil {
				t.Fatal("directory accepted as CA file")
			}
			if runtime.GOOS == "windows" {
				return
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".original", path); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(dir); err == nil {
				t.Fatal("symlink accepted as CA file")
			}
		})
	}
}
