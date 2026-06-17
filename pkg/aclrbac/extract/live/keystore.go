// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// keystoreFormat identifies a keystore container format. We detect via
// file extension because the Kafka client.properties contract names
// these files conventionally — JKS for legacy Java apps, PKCS12 for
// modern interop, PEM for Linux toolchains. Operators who use weird
// extensions can rename; we don't sniff bytes.
type keystoreFormat int

const (
	formatUnknown keystoreFormat = iota
	formatPEM
	formatPKCS12
	formatJKS
)

func (f keystoreFormat) String() string {
	switch f {
	case formatPEM:
		return "PEM"
	case formatPKCS12:
		return "PKCS12"
	case formatJKS:
		return "JKS"
	}
	return "unknown"
}

// detectKeystoreFormat picks a format from the file extension. The
// Kafka client.properties convention is .pem / .crt / .cer (PEM),
// .p12 / .pfx (PKCS12), .jks / .keystore (JKS).
func detectKeystoreFormat(path string) keystoreFormat {
	low := strings.ToLower(path)
	switch {
	case strings.HasSuffix(low, ".pem"),
		strings.HasSuffix(low, ".crt"),
		strings.HasSuffix(low, ".cer"):
		return formatPEM
	case strings.HasSuffix(low, ".p12"),
		strings.HasSuffix(low, ".pfx"):
		return formatPKCS12
	case strings.HasSuffix(low, ".jks"),
		strings.HasSuffix(low, ".keystore"):
		return formatJKS
	}
	return formatUnknown
}

// loadTruststore reads a trust store from path and returns a CertPool.
// password is ignored for PEM (which has no encryption layer at this
// granularity) and required for JKS; PKCS12 trust stores are typically
// password-less but accept one if set.
func loadTruststore(path, password string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ssl.truststore.location: read %s: %w", path, err)
	}

	switch detectKeystoreFormat(path) {
	case formatPEM:
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("ssl.truststore.location: no PEM blocks parsed from %s", path)
		}
		return pool, nil

	case formatPKCS12:
		certs, err := pkcs12.DecodeTrustStore(data, password)
		if err != nil {
			return nil, fmt.Errorf("ssl.truststore.location: decode PKCS12 %s: %w", path, err)
		}
		pool := x509.NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
		return pool, nil

	case formatJKS:
		ks := keystore.New()
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("ssl.truststore.location: open %s: %w", path, err)
		}
		defer f.Close()
		if err := ks.Load(f, []byte(password)); err != nil {
			return nil, fmt.Errorf("ssl.truststore.location: load JKS %s: %w", path, err)
		}
		pool := x509.NewCertPool()
		for _, alias := range ks.Aliases() {
			entry, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				// Skip aliases that aren't trusted-cert entries (e.g.,
				// the rare JKS that mixes trust and key material).
				continue
			}
			c, err := x509.ParseCertificate(entry.Certificate.Content)
			if err != nil {
				return nil, fmt.Errorf("ssl.truststore.location: parse cert under alias %q: %w", alias, err)
			}
			pool.AddCert(c)
		}
		return pool, nil

	default:
		return nil, fmt.Errorf("ssl.truststore.location: unrecognised file extension on %s (want .pem/.crt/.cer, .p12/.pfx, or .jks/.keystore)", path)
	}
}

// loadKeystore reads a keystore containing a client cert + private key
// pair. password is required for PKCS12 and JKS (typically the same
// password protects both the keystore and the individual key entry).
// PEM keystores accept a password too if they contain an encrypted
// PRIVATE KEY block — currently rejected; see live_opts.go's existing
// error message for the workaround.
// keyPassword protects the individual private-key entry (Java's
// ssl.key.password). For JKS it may differ from the store password; an empty
// keyPassword falls back to the store password. PKCS12 uses a single password.
func loadKeystore(path, password, keyPassword string) (tls.Certificate, error) {
	entryPassword := keyPassword
	if entryPassword == "" {
		entryPassword = password
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ssl.keystore.location: read %s: %w", path, err)
	}

	switch detectKeystoreFormat(path) {
	case formatPEM:
		// PEM keystores still go through tls.LoadX509KeyPair so the
		// existing v1 behaviour is preserved (caller handles
		// ssl.key.password rejection separately).
		return tls.LoadX509KeyPair(path, path)

	case formatPKCS12:
		priv, cert, caCerts, err := pkcs12.DecodeChain(data, password)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("ssl.keystore.location: decode PKCS12 %s: %w", path, err)
		}
		signer, ok := priv.(crypto.Signer)
		if !ok {
			return tls.Certificate{}, fmt.Errorf("ssl.keystore.location: PKCS12 %s contains unsupported private key type %T", path, priv)
		}
		// Include the CA/intermediate certs stored in the keystore (leaf
		// first), so brokers that require the intermediate in the client's
		// handshake chain succeed — discarding them sends a leaf-only chain.
		chain := make([][]byte, 0, 1+len(caCerts))
		chain = append(chain, cert.Raw)
		for _, ca := range caCerts {
			chain = append(chain, ca.Raw)
		}
		return tls.Certificate{
			Certificate: chain,
			PrivateKey:  signer,
			Leaf:        cert,
		}, nil

	case formatJKS:
		ks := keystore.New()
		f, err := os.Open(path)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("ssl.keystore.location: open %s: %w", path, err)
		}
		defer f.Close()
		if err := ks.Load(f, []byte(password)); err != nil {
			return tls.Certificate{}, fmt.Errorf("ssl.keystore.location: load JKS %s: %w", path, err)
		}
		sawPrivateKeyEntry := false
		for _, alias := range ks.Aliases() {
			if !ks.IsPrivateKeyEntry(alias) {
				continue
			}
			sawPrivateKeyEntry = true
			entry, err := ks.GetPrivateKeyEntry(alias, []byte(entryPassword))
			if err != nil {
				continue
			}
			parsedKey, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
			if err != nil {
				// Fall back to PKCS#1 RSA if the JKS shipped an older key.
				parsedKey, err = x509.ParsePKCS1PrivateKey(entry.PrivateKey)
				if err != nil {
					return tls.Certificate{}, fmt.Errorf("ssl.keystore.location: parse key under alias %q: %w", alias, err)
				}
			}
			signer, ok := parsedKey.(crypto.Signer)
			if !ok {
				return tls.Certificate{}, fmt.Errorf("ssl.keystore.location: JKS alias %q contains unsupported private key type %T", alias, parsedKey)
			}
			if len(entry.CertificateChain) == 0 {
				return tls.Certificate{}, fmt.Errorf("ssl.keystore.location: alias %q has private key but no cert chain", alias)
			}
			chain := make([][]byte, 0, len(entry.CertificateChain))
			var leaf *x509.Certificate
			for i, c := range entry.CertificateChain {
				chain = append(chain, c.Content)
				if i == 0 {
					leaf, err = x509.ParseCertificate(c.Content)
					if err != nil {
						return tls.Certificate{}, fmt.Errorf("ssl.keystore.location: parse leaf cert: %w", err)
					}
				}
			}
			return tls.Certificate{
				Certificate: chain,
				PrivateKey:  signer,
				Leaf:        leaf,
			}, nil
		}
		if sawPrivateKeyEntry {
			return tls.Certificate{}, errors.New("ssl.keystore.location: JKS contains private-key entries but none decrypted; check ssl.keystore.password and ssl.key.password")
		}
		return tls.Certificate{}, errors.New("ssl.keystore.location: no private-key entry found in JKS")

	default:
		return tls.Certificate{}, fmt.Errorf("ssl.keystore.location: unrecognised file extension on %s", path)
	}
}

// pkcsToPEM is a tiny helper for the test fixtures. Production code
// reads PEM files; this lets unit tests construct one in memory.
func pkcsToPEM(der []byte, blockType string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}
