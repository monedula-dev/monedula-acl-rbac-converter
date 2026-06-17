// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build !windows

package rundir_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
)

// TestLock_FilePermissionsAre0600 asserts the POSIX spec promise that
// the per-run-directory .lock file is written with mode 0600 (owner
// read/write only). The lockfile carries PID + hostname + start time;
// world-readable would leak host identity to anyone with access to
// the shared filesystem the run directory might sit on.
//
// Skipped on Windows: file mode bits are not enforced there, and the
// implementation uses a different code path for liveness probing.
func TestLock_FilePermissionsAre0600(t *testing.T) {
	dir := t.TempDir()

	lock, err := rundir.Acquire(dir, "apply")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() {
		if err := lock.Release(); err != nil {
			t.Errorf("release: %v", err)
		}
	}()

	info, err := os.Stat(filepath.Join(dir, ".lock"))
	if err != nil {
		t.Fatalf("stat lock: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Errorf(".lock mode: got %#o, want %#o", got, want)
	}
}
