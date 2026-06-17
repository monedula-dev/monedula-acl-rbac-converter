// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live

import (
	"crypto/tls"
	"fmt"
	"sort"
	"strings"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/log"
)

// buildKgoOpts translates an optional Kafka client.properties file
// into a slice of kgo client options. It also annotates the provided
// logger with USED/SKIPPED lines per config key so the extract.log
// records exactly which knobs were honored.
//
// The supported keys are:
//   - security.protocol ∈ {PLAINTEXT, SSL, SASL_PLAINTEXT, SASL_SSL}
//   - sasl.mechanism ∈ {PLAIN, SCRAM-SHA-256, SCRAM-SHA-512}
//   - sasl.jaas.config (PlainLoginModule / ScramLoginModule)
//   - ssl.truststore.location (PEM / PKCS12 / JKS — extension-detected)
//   - ssl.truststore.password (used for PKCS12 / JKS)
//   - ssl.keystore.location (PEM / PKCS12 / JKS — extension-detected)
//   - ssl.keystore.password (used for PKCS12 / JKS)
//   - ssl.key.password (PEM only; non-empty value is rejected with a
//     pointer to `openssl rsa -in encrypted.pem -out decrypted.pem`)
//   - ssl.endpoint.identification.algorithm ("" disables hostname
//     verification — printed to stderr as a loud warning)
//
// Any other recognized key combination — an unsupported SASL mechanism,
// an unrecognised store extension — surfaces as an error rather than
// silently dropping configuration.
func buildKgoOpts(bootstrap []string, propsPath string, log *extract.Logger) ([]kgo.Opt, error) {
	opts := []kgo.Opt{kgo.SeedBrokers(bootstrap...)}
	if propsPath == "" {
		return opts, nil
	}

	props, err := parseProperties(propsPath)
	if err != nil {
		return nil, err
	}

	// Track which keys we actually consumed so we can emit USED vs.
	// SKIPPED lines in stable, alphabetical order at the end.
	used := map[string]bool{}

	protocol := strings.ToUpper(strings.TrimSpace(props["security.protocol"]))
	if protocol == "" {
		protocol = "PLAINTEXT"
	}
	switch protocol {
	case "PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL":
		// recognized
	default:
		return nil, fmt.Errorf("security.protocol: unsupported value %q (want PLAINTEXT, SSL, SASL_PLAINTEXT, or SASL_SSL)", protocol)
	}
	if _, set := props["security.protocol"]; set {
		used["security.protocol"] = true
	}

	if protocol == "SSL" || protocol == "SASL_SSL" {
		tlsCfg, err := buildTLSConfig(props, used)
		if err != nil {
			return nil, err
		}
		opts = append(opts, kgo.DialTLSConfig(tlsCfg))
	}

	if protocol == "SASL_PLAINTEXT" || protocol == "SASL_SSL" {
		mech, err := buildSASLMechanism(props, used)
		if err != nil {
			return nil, err
		}
		opts = append(opts, kgo.SASL(mech))
	}

	// Log USED/SKIPPED in alphabetical order — deterministic so
	// extract.log diffs cleanly across runs.
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if used[k] {
			log.Logf("USED config key=%s", k)
		} else {
			log.Logf("SKIPPED config key=%s", k)
		}
	}

	return opts, nil
}

// buildTLSConfig assembles a *tls.Config from the SSL-related entries
// in the parsed properties map. Truststore and keystore files are
// detected by extension and decrypted in-process: PEM (.pem/.crt/.cer),
// PKCS12 (.p12/.pfx), and JKS (.jks/.keystore) are all accepted. See
// loadTruststore / loadKeystore in keystore.go for the format-specific
// details.
func buildTLSConfig(props map[string]string, used map[string]bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if trustPath := props["ssl.truststore.location"]; trustPath != "" {
		used["ssl.truststore.location"] = true
		password := props["ssl.truststore.password"]
		if password != "" {
			used["ssl.truststore.password"] = true
		}
		pool, err := loadTruststore(trustPath, password)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}

	if keystorePath := props["ssl.keystore.location"]; keystorePath != "" {
		used["ssl.keystore.location"] = true
		password := props["ssl.keystore.password"]
		if password != "" {
			used["ssl.keystore.password"] = true
		}

		// PEM keystores still cannot carry an encrypted private key in v1.
		// Keep the explicit rejection so operators see a clear pointer to
		// `openssl rsa -in encrypted.pem -out decrypted.pem` instead of a
		// vague handshake failure.
		if detectKeystoreFormat(keystorePath) == formatPEM {
			if pw := strings.TrimSpace(props["ssl.key.password"]); pw != "" {
				used["ssl.key.password"] = true
				return nil, fmt.Errorf("ssl.key.password is set on a PEM keystore but encrypted PEM keys " +
					"are not supported in v1; decrypt the key first with " +
					"`openssl rsa -in encrypted.pem -out decrypted.pem`, or use the .p12/.jks variant " +
					"(which now decrypts in-process)")
			}
		}

		keyPassword := strings.TrimSpace(props["ssl.key.password"])
		if keyPassword != "" {
			used["ssl.key.password"] = true
		}
		cert, err := loadKeystore(keystorePath, password, keyPassword)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if v, set := props["ssl.endpoint.identification.algorithm"]; set {
		used["ssl.endpoint.identification.algorithm"] = true
		if strings.TrimSpace(v) == "" {
			cfg.InsecureSkipVerify = true //nolint:gosec // explicit operator opt-in via empty algorithm setting
			log.Warn("hostname verification disabled via ssl.endpoint.identification.algorithm=''",
				"impact", "connections vulnerable to MITM; this is what Java's empty-string convention means")
		}
	}

	return cfg, nil
}

// buildSASLMechanism returns the franz-go sasl.Mechanism implied by
// sasl.mechanism + sasl.jaas.config. Only PLAIN, SCRAM-SHA-256, and
// SCRAM-SHA-512 are handled in v1; anything else is an explicit error.
func buildSASLMechanism(props map[string]string, used map[string]bool) (sasl.Mechanism, error) {
	mechName := strings.ToUpper(strings.TrimSpace(props["sasl.mechanism"]))
	if mechName == "" {
		return nil, fmt.Errorf("sasl.mechanism is required when security.protocol uses SASL")
	}
	used["sasl.mechanism"] = true

	jaas := props["sasl.jaas.config"]
	if jaas == "" {
		return nil, fmt.Errorf("sasl.jaas.config is required when security.protocol uses SASL")
	}
	used["sasl.jaas.config"] = true

	user, pass, err := parseJAASUserPass(jaas)
	if err != nil {
		return nil, fmt.Errorf("sasl.jaas.config: %w", err)
	}

	switch mechName {
	case "PLAIN":
		return plain.Auth{User: user, Pass: pass}.AsMechanism(), nil
	case "SCRAM-SHA-256":
		return scram.Auth{User: user, Pass: pass}.AsSha256Mechanism(), nil
	case "SCRAM-SHA-512":
		return scram.Auth{User: user, Pass: pass}.AsSha512Mechanism(), nil
	default:
		return nil, fmt.Errorf("sasl.mechanism: unsupported value %q (want PLAIN, SCRAM-SHA-256, or SCRAM-SHA-512)", mechName)
	}
}
