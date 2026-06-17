// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests drive buildTLSConfig directly (the live extractor's TLS
// assembly from a parsed client.properties map). The happy-path truststore
// branch is covered via buildKgoOpts in live_opts_test.go; here we pin the
// security-relevant branches that file doesn't reach: hostname-verification
// opt-out, missing-store error propagation, the keystore (mTLS) branch, and
// the encrypted-PEM-key rejection.

// TestBuildTLSConfig_InsecureViaEmptyAlgorithm is the security-sensitive
// branch: Java's convention is that an empty
// ssl.endpoint.identification.algorithm disables hostname verification.
// buildTLSConfig must honour that by setting InsecureSkipVerify — and only
// for the empty value, never for a non-empty one like "https".
func TestBuildTLSConfig_InsecureViaEmptyAlgorithm(t *testing.T) {
	used := map[string]bool{}
	cfg, err := buildTLSConfig(map[string]string{
		"ssl.endpoint.identification.algorithm": "",
	}, used)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("empty ssl.endpoint.identification.algorithm must disable hostname verification")
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
