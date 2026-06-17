// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSelfSignedPEM writes a self-signed cert (and its key) as PEM files in
// a TempDir and returns their paths. Used to exercise the CA-cert and mTLS
// branches of buildTLSConfig without committing binary fixtures.
func writeSelfSignedPEM(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mds-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestBuildTLSConfig_Default: no TLS material -> TLS 1.2 floor, verification on.
func TestBuildTLSConfig_Default(t *testing.T) {
	cfg, err := buildTLSConfig(Config{URL: "https://mds"})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg.MinVersion != tlsVersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2 floor (%x)", cfg.MinVersion, tlsVersionTLS12)
	}
	if cfg.InsecureSkipVerify {
		t.Error("verification must be ON by default")
	}
	if cfg.RootCAs != nil {
		t.Error("no CA configured -> RootCAs must stay nil (use system roots)")
	}
	if len(cfg.Certificates) != 0 {
		t.Error("no client cert configured -> Certificates must be empty")
	}
}

// TestBuildTLSConfig_InsecureSkipVerify: the flag sets InsecureSkipVerify.
func TestBuildTLSConfig_InsecureSkipVerify(t *testing.T) {
	cfg, err := buildTLSConfig(Config{URL: "https://mds", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify=true must propagate to tls.Config")
	}
}

// TestBuildTLSConfig_CACert: a valid CA file populates RootCAs.
func TestBuildTLSConfig_CACert(t *testing.T) {
	certPath, _ := writeSelfSignedPEM(t)
	cfg, err := buildTLSConfig(Config{URL: "https://mds", CACertPath: certPath})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("a valid CA file must populate RootCAs")
	}
}

// TestBuildTLSConfig_CACertMissingFile: a missing CA path is a hard error,
// not a silent fall-through to system roots (which would defeat the
// operator's intent to pin a private CA).
func TestBuildTLSConfig_CACertMissingFile(t *testing.T) {
	_, err := buildTLSConfig(Config{URL: "https://mds", CACertPath: filepath.Join(t.TempDir(), "nope.pem")})
	if err == nil {
		t.Fatal("expected error for missing CA cert file")
	}
	if !strings.Contains(err.Error(), "read CA cert") {
		t.Errorf("error should name the CA-read failure; got: %v", err)
	}
}

// TestBuildTLSConfig_CACertNoCertsInPEM: a file that parses as PEM but
// contains no certificate must error rather than silently leaving an empty
// pool (which would reject every server cert with a confusing handshake
// error far from the cause).
func TestBuildTLSConfig_CACertNoCertsInPEM(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(bad, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := buildTLSConfig(Config{URL: "https://mds", CACertPath: bad})
	if err == nil {
		t.Fatal("expected error for PEM with no certificates")
	}
	if !strings.Contains(err.Error(), "no certificates") {
		t.Errorf("error should explain the empty PEM; got: %v", err)
	}
}

// TestBuildTLSConfig_MTLS: a client cert+key pair populates Certificates.
func TestBuildTLSConfig_MTLS(t *testing.T) {
	certPath, keyPath := writeSelfSignedPEM(t)
	cfg, err := buildTLSConfig(Config{URL: "https://mds", ClientCertPath: certPath, ClientKeyPath: keyPath})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("mTLS pair must load exactly one client certificate; got %d", len(cfg.Certificates))
	}
}

// TestBuildTLSConfig_MTLSBadKeyPair: a mismatched/unreadable key surfaces an
// error rather than starting with a half-configured client cert.
func TestBuildTLSConfig_MTLSBadKeyPair(t *testing.T) {
	certPath, _ := writeSelfSignedPEM(t)
	_, err := buildTLSConfig(Config{
		URL: "https://mds", ClientCertPath: certPath, ClientKeyPath: filepath.Join(t.TempDir(), "missing.key"),
	})
	if err == nil {
		t.Fatal("expected error loading client cert with a missing key file")
	}
	if !strings.Contains(err.Error(), "load client cert") {
		t.Errorf("error should name the client-cert load failure; got: %v", err)
	}
}

// tlsVersionTLS12 mirrors crypto/tls.VersionTLS12 so the assertion reads
// without importing crypto/tls into the test for one constant.
const tlsVersionTLS12 = 0x0303
