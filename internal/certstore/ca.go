// Package certstore creates and uses a private local CA without OpenSSL.
package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cquark7/withhold/internal/localstate"
)

type CA struct {
	Certificate *x509.Certificate
	Key         *ecdsa.PrivateKey
	mu          sync.Mutex
	cache       map[string]*tls.Certificate
}

func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic("cannot generate certificate serial")
	}
	return n
}
func Init(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	lock := filepath.Join(dir, ".ca-init.lock")
	if err := os.Mkdir(lock, 0700); err != nil {
		return errors.New("CA initialization is locked")
	}
	defer os.Remove(lock)
	for _, name := range []string{"ca.key", "ca.crt"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return errors.New("CA files already exist or cannot be inspected; refusing to overwrite")
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Withhold Local CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	// Publish only complete files. A second-file failure removes our own key;
	// a process crash leaving a partial pair is refused on the next attempt.
	write := func(name string, data []byte, mode os.FileMode) error {
		f, e := os.CreateTemp(dir, ".ca-*")
		if e != nil {
			return e
		}
		defer os.Remove(f.Name())
		e = f.Chmod(mode)
		if e == nil && name == "ca.key" {
			e = localstate.Protect(f.Name())
		}
		if e == nil {
			_, e = f.Write(data)
		}
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		return os.Link(f.Name(), filepath.Join(dir, name))
	}
	if err = write("ca.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return err
	}
	if err = write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		_ = os.Remove(filepath.Join(dir, "ca.key"))
	}
	return err
}
func Load(dir string) (*CA, error) {
	// Check file types before reading: a pipe or device must not stall startup.
	if err := localstate.CheckPrivate(filepath.Join(dir, "ca.key")); err != nil {
		return nil, errors.New("CA key must be an owned private regular file (0600 on POSIX; protected current-user ACL on Windows)")
	}
	if err := localstate.Regular(filepath.Join(dir, "ca.crt")); err != nil {
		return nil, errors.New("CA certificate must be a regular file")
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, errors.New("cannot load CA certificate/key")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return nil, errors.New("CA is invalid or expired")
	}
	return &CA{Certificate: cert, Key: key, cache: make(map[string]*tls.Certificate)}, nil
}
func (c *CA) Fingerprint() string {
	sum := sha1.Sum(c.Certificate.Raw)
	return hex.EncodeToString(sum[:])
}
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert := c.cache[host]; cert != nil && time.Now().Add(time.Minute).Before(cert.Leaf.NotAfter) {
		return cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if cert.NotAfter.After(c.Certificate.NotAfter) {
		cert.NotAfter = c.Certificate.NotAfter
	}
	if !time.Now().Before(cert.NotAfter) {
		return nil, errors.New("CA has expired")
	}
	if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else {
		cert.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, c.Certificate, &key.PublicKey, c.Key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pair := &tls.Certificate{Certificate: [][]byte{der, c.Certificate.Raw}, PrivateKey: key, Leaf: parsed}
	if len(c.cache) >= 128 {
		clear(c.cache)
	}
	c.cache[host] = pair
	return pair, nil
}
