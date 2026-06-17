// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package rundir resolves, creates, and manages the per-invocation run
// directory described in spec §4.1.
package rundir

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ResolveOptions feeds the §4.1 resolution order.
type ResolveOptions struct {
	// ExplicitRunDir is the value of --run-dir (highest priority).
	ExplicitRunDir string
	// Out is the value of --out (a file or a directory).
	Out string
	// InputArtifact is the primary input file the command consumes
	// (e.g., --acls for plan; --plan for apply/verify/emit). The run dir is
	// inferred as the artifact's parent directory.
	InputArtifact string
	// Now is injected for tests; defaults to time.Now.
	Now func() time.Time
}

// Resolve returns the run directory path for an invocation, following the
// five-step order in §4.1. The directory may not exist yet; call Ensure to
// create it.
func Resolve(opts ResolveOptions) (string, error) {
	if opts.ExplicitRunDir != "" {
		return opts.ExplicitRunDir, nil
	}
	if opts.Out != "" {
		return filepath.Dir(opts.Out), nil
	}
	if opts.InputArtifact != "" {
		return filepath.Dir(opts.InputArtifact), nil
	}
	if env := os.Getenv("MONEDULA_ACL_RBAC_RUN_DIR"); env != "" {
		return env, nil
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cwd: %w", err)
	}
	// The auto-generated name has 1-second granularity and Ensure tolerates an
	// existing dir, so two invocations in the same wall-clock second would
	// otherwise share a run dir and overwrite each other's artefacts.
	// Disambiguate with a -N suffix when the timestamped name already exists.
	// (Only the auto path is disambiguated; an explicit --run-dir is honored
	// verbatim.)
	base := filepath.Join(cwd, "runs", Timestamp(now().UTC()))
	return disambiguate(base), nil
}

// disambiguate returns base if it does not exist, otherwise base-2, base-3, …
// — the first candidate that does not yet exist.
func disambiguate(base string) string {
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return base
	}
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s-%d", base, i)
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
}

// Ensure creates the run directory (and parents) if it does not exist.
// Existing directories are left alone.
//
// Mode 0o700: run-dir children include 0o600 secrets — runtime.env carries
// the per-run RUNTIME_AUTH_TOKEN, MDS endpoints, and credential-source
// references. A traversable / listable parent on a multi-tenant host
// (0o755 was the previous mode) let other local users enumerate run
// timestamps and see WHICH artefacts exist even if they could not read
// them. The token-cache dir is already 0o700; match that here.
func Ensure(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return nil
}

// Timestamp formats a time as the canonical run-directory timestamp.
// Format: 2026-05-21T10-00-00Z (no colons — Windows-safe).
func Timestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15-04-05Z")
}
