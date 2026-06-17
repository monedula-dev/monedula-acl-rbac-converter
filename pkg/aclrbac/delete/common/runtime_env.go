// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package common

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/shell"
)

// RuntimeEnv mirrors the fields written to runs/<ts>/runtime.env.
type RuntimeEnv struct {
	BootstrapServers string
	CommandConfig    string
	MDSURL           string
	MDSUser          string
	MDSPasswordFile  string
	MDSTokenFile     string
	MDSCACert        string
	MDSClientCert    string
	MDSClientKey     string
	// InsecureSkipVerify mirrors --mds-insecure-skip-verify. It must be
	// carried through runtime.env so the per-ACL delete-deny-one re-check
	// rebuilds the MDS client with the same TLS posture the operator chose
	// at generation time; otherwise a private-CA MDS that only worked with
	// the flag set fails TLS verification at script-execution time.
	InsecureSkipVerify bool
	// MaxRetries mirrors --mds-max-retries. Carried through so the operator's
	// retry tuning survives into the script-time re-check instead of
	// silently reverting to the package default.
	MaxRetries int
	AuthToken  string
}

// WriteRuntimeEnv writes runtime.env into runDir with mode 0600. Returns
// the absolute path.
func WriteRuntimeEnv(runDir string, env RuntimeEnv) (string, error) {
	path := filepath.Join(runDir, "runtime.env")

	var b strings.Builder
	writeKV(&b, "BOOTSTRAP_SERVER", env.BootstrapServers)
	writeKV(&b, "COMMAND_CONFIG", env.CommandConfig)
	writeKV(&b, "MDS_URL", env.MDSURL)
	writeKV(&b, "MDS_USER", env.MDSUser)
	writeKV(&b, "MDS_PASSWORD_FILE", env.MDSPasswordFile)
	writeKV(&b, "MDS_TOKEN_FILE", env.MDSTokenFile)
	writeKV(&b, "MDS_CA_CERT", env.MDSCACert)
	writeKV(&b, "MDS_CLIENT_CERT", env.MDSClientCert)
	writeKV(&b, "MDS_CLIENT_KEY", env.MDSClientKey)
	// Always emit these two so the absence of a key in an older runtime.env
	// is distinguishable from an explicit false/0. writeKV skips empty
	// strings; these scalars are written unconditionally.
	fmt.Fprintf(&b, "MDS_INSECURE_SKIP_VERIFY=%t\n", env.InsecureSkipVerify)
	fmt.Fprintf(&b, "MDS_MAX_RETRIES=%d\n", env.MaxRetries)
	writeKV(&b, "RUNTIME_AUTH_TOKEN", env.AuthToken)

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// ReadRuntimeEnv parses runtime.env from runDir.
func ReadRuntimeEnv(runDir string) (RuntimeEnv, error) {
	path := filepath.Join(runDir, "runtime.env")
	f, err := os.Open(path)
	if err != nil {
		return RuntimeEnv{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var env RuntimeEnv
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		switch k {
		case "BOOTSTRAP_SERVER":
			env.BootstrapServers = v
		case "COMMAND_CONFIG":
			env.CommandConfig = v
		case "MDS_URL":
			env.MDSURL = v
		case "MDS_USER":
			env.MDSUser = v
		case "MDS_PASSWORD_FILE":
			env.MDSPasswordFile = v
		case "MDS_TOKEN_FILE":
			env.MDSTokenFile = v
		case "MDS_CA_CERT":
			env.MDSCACert = v
		case "MDS_CLIENT_CERT":
			env.MDSClientCert = v
		case "MDS_CLIENT_KEY":
			env.MDSClientKey = v
		case "MDS_INSECURE_SKIP_VERIFY":
			env.InsecureSkipVerify = parseBool(v)
		case "MDS_MAX_RETRIES":
			// Lenient: a malformed or missing value falls back to 0, which
			// NewClient treats as "no retries". We never want a parse error
			// here to abort the per-ACL re-check at script-execution time.
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				env.MaxRetries = n
			}
		case "RUNTIME_AUTH_TOKEN":
			env.AuthToken = v
		}
	}
	return env, sc.Err()
}

func writeKV(b *strings.Builder, key, val string) {
	if val == "" {
		return
	}
	fmt.Fprintf(b, "%s=%s\n", key, shell.Quote(val))
}

// parseBool reads a runtime.env boolean leniently. The writer always emits
// "true"/"false" (Go's %t), but we also accept "1"/"yes" so a hand-edited
// runtime.env behaves intuitively. Anything else (including empty) is false.
func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}

func splitKV(line string) (key, val string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", false
	}
	key = line[:i]
	v := line[i+1:]
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		v = v[1 : len(v)-1]
		v = strings.ReplaceAll(v, `'\''`, "'")
	}
	return key, v, true
}
