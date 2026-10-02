// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests drive buildTLSConfig directly (the live extractor's TLS
// assembly from a parsed client.properties map). The happy-path truststore
// branch is covered via buildKgoOpts in live_opts_test.go; here we pin the
// security-relevant branches that file doesn't reach: hostname-verification
// opt-out (through real handshakes), missing-store error propagation, the
// keystore (mTLS) branch, and the encrypted-PEM-key rejection.

// TestBuildTLSConfig_EndpointIdentification is the security-sensitive
// branch, driven through real handshakes. Java's convention is that an empty
// ssl.endpoint.identification.algorithm disables the hostname check ONLY:
// the server's chain is still validated against the truststore. crypto/tls
// has no hostname-only switch, so an implementation that simply sets
// InsecureSkipVerify accepts any certificate at all — a MITM could then
// harvest the SASL credentials sent over the connection.
func TestBuildTLSConfig_EndpointIdentification(t *testing.T) {
	root, rootKey := genCert(t, "test-root-ca")
	other, _ := genCert(t, "unrelated-ca")
	inter, interKey := issueCert(t, root, rootKey, "test-intermediate-ca", true)

	// Both servers listen on 127.0.0.1 but present a cert for another name,
	// so the hostname check can never pass.
	const host = "kafka.example.invalid"
	leaf, leafKey := issueCert(t, root, rootKey, host, false)
	direct := startTLSServer(t, tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey})
	viaInterLeaf, viaInterKey := issueCert(t, inter, interKey, host, false)
	viaInter := startTLSServer(t, tls.Certificate{Certificate: [][]byte{viaInterLeaf.Raw, inter.Raw}, PrivateKey: viaInterKey})

	trustRoot := writePEMTruststore(t, root)
	trustOther := writePEMTruststore(t, other)

	const (
		ok          = ""
		badHostname = "hostname"
		badChain    = "chain"
	)
	cases := []struct {
		name  string
		props map[string]string
		addr  string
		want  string
	}{
		{"hostname is checked when the key is unset", map[string]string{
			"ssl.truststore.location": trustRoot,
		}, direct, badHostname},
		{"hostname is checked for https", map[string]string{
			"ssl.truststore.location":               trustRoot,
			"ssl.endpoint.identification.algorithm": "https",
		}, direct, badHostname},
		{"empty algorithm skips the hostname check", map[string]string{
			"ssl.truststore.location":               trustRoot,
			"ssl.endpoint.identification.algorithm": "",
		}, direct, ok},
		{"empty algorithm still rejects a chain outside the truststore", map[string]string{
			"ssl.truststore.location":               trustOther,
			"ssl.endpoint.identification.algorithm": "",
		}, direct, badChain},
		{"empty algorithm builds the chain through server-sent intermediates", map[string]string{
			"ssl.truststore.location":               trustRoot,
			"ssl.endpoint.identification.algorithm": "",
		}, viaInter, ok},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := buildTLSConfig(tc.props, map[string]bool{})
			if err != nil {
				t.Fatalf("buildTLSConfig: %v", err)
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", tc.addr, cfg)
			if err == nil {
				conn.Close()
			}
			var hostErr x509.HostnameError
			var authErr x509.UnknownAuthorityError
			switch {
			case tc.want == ok && err != nil:
				t.Fatalf("handshake failed, want success: %v", err)
			case tc.want == badHostname && !errors.As(err, &hostErr):
				t.Fatalf("want a hostname verification error, got: %v", err)
			case tc.want == badChain && !errors.As(err, &authErr):
				t.Fatalf("want an unknown-authority error, got: %v", err)
			}
		})
	}
}

func TestBuildTLSConfig_EmptyAlgorithmMarkedUsed(t *testing.T) {
	used := map[string]bool{}
	if _, err := buildTLSConfig(map[string]string{
		"ssl.endpoint.identification.algorithm": "",
	}, used); err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if !used["ssl.endpoint.identification.algorithm"] {
		t.Error("the key must be marked USED so extract.log records the opt-out")
	}
}

func TestBuildTLSConfig_VerificationStaysOnForNonEmptyAlgorithm(t *testing.T) {
	used := map[string]bool{}
	cfg, err := buildTLSConfig(map[string]string{
		"ssl.endpoint.identification.algorithm": "https",
	}, used)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Error("a non-empty algorithm (https) must NOT disable verification")
	}
}

// TestBuildTLSConfig_MissingTruststorePropagates: a configured truststore
// path that can't be loaded must error rather than silently producing a
// config with the system roots (which would connect to a different trust
// anchor than the operator intended).
func TestBuildTLSConfig_MissingTruststorePropagates(t *testing.T) {
	used := map[string]bool{}
	_, err := buildTLSConfig(map[string]string{
		"ssl.truststore.location": filepath.Join(t.TempDir(), "nope.jks"),
		"ssl.truststore.password": "changeit",
	}, used)
	if err == nil {
		t.Fatal("expected error for a missing truststore file")
	}
}

// TestBuildTLSConfig_KeystoreBranch exercises the mTLS keystore path through
// buildTLSConfig (not just loadKeystore): a PKCS12 keystore populates
// cfg.Certificates and the location/password keys are marked USED.
func TestBuildTLSConfig_KeystoreBranch(t *testing.T) {
	cert, priv := genCert(t, "client-tlscfg")
	ksPath := writePKCS12Keystore(t, cert, priv, "changeit")
	used := map[string]bool{}
	cfg, err := buildTLSConfig(map[string]string{
		"ssl.keystore.location": ksPath,
		"ssl.keystore.password": "changeit",
	}, used)
	if err != nil {
		t.Fatalf("buildTLSConfig with keystore: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("keystore must populate exactly one client certificate; got %d", len(cfg.Certificates))
	}
	if !used["ssl.keystore.location"] || !used["ssl.keystore.password"] {
		t.Error("keystore location + password must be marked USED")
	}
}

// TestBuildTLSConfig_PEMKeystoreWithKeyPasswordRejected pins the explicit
// refusal of an encrypted PEM key: rather than a vague handshake failure
// later, the operator gets a pointer to openssl. (PKCS12/JKS decrypt
// in-process; PEM does not in v1.)
func TestBuildTLSConfig_PEMKeystoreWithKeyPasswordRejected(t *testing.T) {
	cert, _ := genCert(t, "client-pem-enc")
	pemPath := filepath.Join(t.TempDir(), "client.pem")
	if err := os.WriteFile(pemPath, pkcsToPEM(cert.Raw, "CERTIFICATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	_, err := buildTLSConfig(map[string]string{
		"ssl.keystore.location": pemPath,
		"ssl.key.password":      "supersecret",
	}, used)
	if err == nil {
		t.Fatal("expected rejection of an encrypted PEM key (ssl.key.password set on a .pem keystore)")
	}
	if !strings.Contains(err.Error(), "encrypted PEM keys") {
		t.Errorf("error should explain encrypted-PEM-key non-support; got: %v", err)
	}
	if !used["ssl.key.password"] {
		t.Error("ssl.key.password must be marked USED on the rejection path")
	}
}

// TestBuildTLSConfig_Default: no SSL keys -> TLS 1.2 floor, verification on,
// no roots/certs overridden.
func TestBuildTLSConfig_Default(t *testing.T) {
	cfg, err := buildTLSConfig(map[string]string{}, map[string]bool{})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.InsecureSkipVerify {
		t.Error("verification must be ON by default")
	}
	if cfg.RootCAs != nil || len(cfg.Certificates) != 0 {
		t.Error("no SSL material configured -> no RootCAs/Certificates override")
	}
}

// issueCert signs a certificate for cn with parent. isCA=false yields a TLS
// server leaf with cn as its only DNS SAN; isCA=true yields an intermediate.
func issueCert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, cn string, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tmpl.DNSNames = []string{cn}
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &priv.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

func writePEMTruststore(t *testing.T, ca *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "truststore.pem")
	if err := os.WriteFile(path, pkcsToPEM(ca.Raw, "CERTIFICATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// startTLSServer serves cert on a loopback port and completes the server
// side of every handshake; the client's verification verdict is what tests
// assert on.
func startTLSServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()
	return ln.Addr().String()
}

// keystoreFormat.String is a one-line dispatcher; a single cheap assertion
// pins the format-name strings used in error/log messages.
func TestKeystoreFormatString(t *testing.T) {
	cases := map[keystoreFormat]string{
		formatPEM:     "PEM",
		formatPKCS12:  "PKCS12",
		formatJKS:     "JKS",
		formatUnknown: "unknown",
	}
	for f, want := range cases {
		if got := f.String(); got != want {
			t.Errorf("keystoreFormat(%d).String() = %q, want %q", f, got, want)
		}
	}
}
