// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package extract defines the common interface and sidecar plumbing for
// every `extract --from X` adapter. Concrete adapters live in subpackages.
package extract

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Adapter is the common interface every input adapter implements. Each
// adapter is responsible for converting its source into a canonical ACLSet
// and recording per-line/per-resource parse status into the Logger.
//
// CFK and K8s adapters additionally surface inventoried
// ConfluentRolebinding records via the 2nd return value — empty for
// sources that don't have a concept of role bindings. When non-empty,
// WriteExtractedSet persists them to existing-bindings.json so the
// planner can mark matching proposed bindings as SKIP_EXISTS.
type Adapter interface {
	// Name returns the value used in --from (e.g., "live", "text", "json").
	Name() string
	// Extract reads from the adapter's configured source and returns:
	//   - the canonical ACL set
	//   - inventoried existing role bindings (CFK / K8s; nil otherwise)
	//   - an ExtractSource describing where the data came from (for audit)
	//   - a Logger holding per-line parse/skip/reject entries
	Extract() (types.ACLSet, []types.Binding, ExtractSource, *Logger, error)
}

// ExtractSource records where an ACLSet came from, written to
// extract-source.json for audit per spec §4.1.
type ExtractSource struct {
	// Kind is the --from value (e.g., "live", "text", "json").
	Kind string `json:"kind"`
	// InputPath is the file path (or directory) for file adapters; empty for
	// live/k8s adapters.
	InputPath string `json:"input_path,omitempty"`
	// InputSHA256 is the SHA-256 hex of the input bytes for file adapters;
	// empty for live/k8s.
	InputSHA256 string `json:"input_sha256,omitempty"`
	// LiveBootstrapServers is the comma-joined bootstrap URL list for
	// --from live; empty otherwise.
	LiveBootstrapServers string `json:"live_bootstrap_servers,omitempty"`
	// K8sServer is the Kubernetes API server URL for --from k8s; empty
	// otherwise.
	K8sServer string `json:"k8s_server,omitempty"`
	// K8sNamespaces lists the namespaces walked for --from k8s; empty
	// otherwise.
	K8sNamespaces []string `json:"k8s_namespaces,omitempty"`
	// Timestamp is when the extraction was performed.
	Timestamp time.Time `json:"timestamp"`
}

// Logger accumulates extract.log entries.
type Logger struct {
	mu      sync.Mutex
	entries []string
}

// NewLogger returns a fresh, empty logger.
func NewLogger() *Logger { return &Logger{} }

// Logf appends one line to the log buffer.
func (l *Logger) Logf(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, fmt.Sprintf(format, args...))
}

// Bytes returns the log buffer as a single \n-joined byte slice.
func (l *Logger) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return []byte(strings.Join(l.entries, "\n") + "\n")
}

// WriteExtractedSet writes acls.json + extract.log + extract-source.json
// into the parent directory of `aclsPath`. `aclsPath` itself becomes acls.json.
// If `bindings` is non-empty, existing-bindings.json is also written
// alongside; an empty/nil list omits the sidecar to avoid stray files.
func WriteExtractedSet(aclsPath string, set types.ACLSet, bindings []types.Binding, src ExtractSource, log *Logger) error {
	dir := filepath.Dir(aclsPath)
	if err := rundir.Ensure(dir); err != nil {
		return err
	}

	if err := rundir.WriteACLs(aclsPath, set); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, "extract.log"), log.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write extract.log: %w", err)
	}

	srcData, err := json.MarshalIndent(src, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal extract-source: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extract-source.json"), srcData, 0o600); err != nil {
		return fmt.Errorf("write extract-source.json: %w", err)
	}

	if len(bindings) > 0 {
		bData, err := json.MarshalIndent(bindings, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal existing-bindings: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "existing-bindings.json"), bData, 0o600); err != nil {
			return fmt.Errorf("write existing-bindings.json: %w", err)
		}
	}

	return nil
}
