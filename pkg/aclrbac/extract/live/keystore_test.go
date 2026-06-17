// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// genCert returns a self-signed cert + its private key. Used by every
// test to build in-memory keystores without committing binary fixtures.
func genCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

func writePKCS12Truststore(t *testing.T, cert *x509.Certificate, password string) string {
	t.Helper()
	// pkcs12.Modern.EncodeTrustStore takes (certs, password); the top-level
	// pkcs12.EncodeTrustStore took (rand, certs, password). We use the
	// Encoder-method form so we don't need to thread crypto/rand explicitly.
	data, err := pkcs12.Modern.EncodeTrustStore([]*x509.Certificate{cert}, password)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "truststore.p12")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writePKCS12Keystore(t *testing.T, cert *x509.Certificate, priv interface{}, password string) string {
	t.Helper()
	// Encoder.Encode signature: (privKey, leafCert, caCerts, password)
	data, err := pkcs12.Modern.Encode(priv, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keystore.p12")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeJKSKeystore builds a JKS keystore protected by storePass with a
// single private-key entry protected by entryPass. JKS encrypts the store
// integrity-tag and each key-entry separately, so the two passwords can
// differ — the wrong-password test exploits this to trigger the
// per-entry decryption error path rather than the store-load error path.
func writeJKSKeystore(t *testing.T, cert *x509.Certificate, priv *ecdsa.PrivateKey, storePass, entryPass string) string {
	t.Helper()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("client", keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   pkcs8,
		CertificateChain: []keystore.Certificate{
			{Type: "X509", Content: cert.Raw},
		},
	}, []byte(entryPass)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keystore.jks")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := ks.Store(f, []byte(storePass)); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeJKSTruststore(t *testing.T, cert *x509.Certificate, password string) string {
	t.Helper()
	ks := keystore.New()
	if err := ks.SetTrustedCertificateEntry("ca", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: keystore.Certificate{
			Type:    "X509",
			Content: cert.Raw,
		},
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "truststore.jks")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := ks.Store(f, []byte(password)); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadTruststore_PEM(t *testing.T) {
	cert, _ := genCert(t, "ca-pem")
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pkcsToPEM(cert.Raw, "CERTIFICATE")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := loadTruststore(path, "")
	if err != nil {
		t.Fatalf("loadTruststore PEM: %v", err)
	}
	if len(pool.Subjects()) == 0 { //nolint:staticcheck // Subjects deprecated but used here for size check in pre-1.23
		t.Error("PEM pool empty")
	}
}

func TestLoadTruststore_PKCS12(t *testing.T) {
	cert, _ := genCert(t, "ca-p12")
	path := writePKCS12Truststore(t, cert, "changeit")
	pool, err := loadTruststore(path, "changeit")
	if err != nil {
		t.Fatalf("loadTruststore PKCS12: %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}
}

func TestLoadTruststore_JKS(t *testing.T) {
	cert, _ := genCert(t, "ca-jks")
	path := writeJKSTruststore(t, cert, "changeit")
	pool, err := loadTruststore(path, "changeit")
	if err != nil {
		t.Fatalf("loadTruststore JKS: %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}
}

func TestLoadTruststore_WrongPassword(t *testing.T) {
	cert, _ := genCert(t, "ca-wrong")
	path := writePKCS12Truststore(t, cert, "rightpass")
	if _, err := loadTruststore(path, "wrongpass"); err == nil {
		t.Fatal("expected error with wrong password")
	}
}

func TestLoadKeystore_PKCS12(t *testing.T) {
	cert, priv := genCert(t, "client-p12")
	path := writePKCS12Keystore(t, cert, priv, "changeit")
	tlsCert, err := loadKeystore(path, "changeit", "")
	if err != nil {
		t.Fatalf("loadKeystore PKCS12: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("no cert in keystore result")
	}
}

// TestLoadKeystore_PKCS12_IncludesCAChain pins that CA/intermediate certs
// stored alongside the leaf in a PKCS12 keystore are included in the
// tls.Certificate chain (leaf first). The old code discarded the caCerts
// return of pkcs12.DecodeChain and sent a leaf-only chain, breaking brokers
// that require the intermediate in the client handshake.
func TestLoadKeystore_PKCS12_IncludesCAChain(t *testing.T) {
	leaf, leafKey := genCert(t, "leaf")
	ca, _ := genCert(t, "intermediate-ca")
	data, err := pkcs12.Modern.Encode(leafKey, leaf, []*x509.Certificate{ca}, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "chain.p12")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	tlsCert, err := loadKeystore(path, "changeit", "")
	if err != nil {
		t.Fatalf("loadKeystore: %v", err)
	}
	if len(tlsCert.Certificate) != 2 {
		t.Errorf("chain length: got %d, want 2 (leaf + CA); CA chain was discarded", len(tlsCert.Certificate))
	}
}

func TestLoadKeystore_JKS(t *testing.T) {
	cert, priv := genCert(t, "client-jks")
	path := writeJKSKeystore(t, cert, priv, "changeit", "changeit")
	tlsCert, err := loadKeystore(path, "changeit", "")
	if err != nil {
		t.Fatalf("loadKeystore JKS: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("no cert in JKS keystore result")
	}
	if _, ok := tlsCert.PrivateKey.(crypto.Signer); !ok {
		t.Fatalf("private key %T does not implement crypto.Signer", tlsCert.PrivateKey)
	}
	if tlsCert.Leaf == nil {
		t.Fatal("leaf cert not parsed")
	}
}

// TestLoadKeystore_JKS_DistinctKeyPassword pins that a JKS whose private-key
// entry is protected by a password different from the store password can be
// loaded by supplying that key password. Java uses ssl.key.password for the
// entry; the old code always used the keystore password and so could never
// open such a keystore.
func TestLoadKeystore_JKS_DistinctKeyPassword(t *testing.T) {
	cert, priv := genCert(t, "client-jks-keypw")
	path := writeJKSKeystore(t, cert, priv, "storepass", "keypass")
	tlsCert, err := loadKeystore(path, "storepass", "keypass")
	if err != nil {
		t.Fatalf("loadKeystore with distinct key password: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("no cert returned")
	}
}

func TestLoadKeystore_PKCS12_WrongPassword(t *testing.T) {
	cert, priv := genCert(t, "client-p12-wrong")
	path := writePKCS12Keystore(t, cert, priv, "rightpass")
	if _, err := loadKeystore(path, "wrongpass", ""); err == nil {
		t.Fatal("expected error with wrong PKCS12 keystore password")
	}
}

func TestLoadKeystore_JKS_WrongPassword(t *testing.T) {
	cert, priv := genCert(t, "client-jks-wrong")
	// Store password matches what loadKeystore is called with, so ks.Load
	// succeeds and we reach the per-entry decryption path. The *entry*
	// password differs, so GetPrivateKeyEntry fails — exercising the
	// "private-key entries but none decrypted" branch from Issue 3.
	path := writeJKSKeystore(t, cert, priv, "rightpass", "entrypass")
	_, err := loadKeystore(path, "rightpass", "")
	if err == nil {
		t.Fatal("expected error with wrong JKS entry password")
	}
	// Asserting on the new error wording from Issue 3 — a regression that
	// reverts the IsPrivateKeyEntry detection would trip this check.
	if !strings.Contains(err.Error(), "JKS contains private-key entries but none decrypted") {
		t.Fatalf("expected 'JKS contains private-key entries but none decrypted' in error, got: %v", err)
	}
}

func TestLoadTruststore_UnknownExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foo.xyz")
	if err := os.WriteFile(path, []byte("not a real truststore"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadTruststore(path, "")
	if err == nil {
		t.Fatal("expected error for unknown extension")
	}
	if !strings.Contains(err.Error(), "unrecognised file extension") {
		t.Fatalf("expected 'unrecognised file extension' in error, got: %v", err)
	}
}

func TestLoadKeystore_UnknownExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foo.xyz")
	if err := os.WriteFile(path, []byte("not a real keystore"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadKeystore(path, "", "")
	if err == nil {
		t.Fatal("expected error for unknown extension")
	}
	if !strings.Contains(err.Error(), "unrecognised file extension") {
		t.Fatalf("expected 'unrecognised file extension' in error, got: %v", err)
	}
}

func TestDetectKeystoreFormat(t *testing.T) {
	cases := []struct {
		path string
		want keystoreFormat
	}{
		{"truststore.pem", formatPEM},
		{"truststore.crt", formatPEM},
		{"truststore.p12", formatPKCS12},
		{"truststore.pfx", formatPKCS12},
		{"truststore.jks", formatJKS},
		{"truststore.keystore", formatJKS},
		{"nonsense.xyz", formatUnknown},
	}
	for _, tc := range cases {
		got := detectKeystoreFormat(tc.path)
		if got != tc.want {
			t.Errorf("detectKeystoreFormat(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
