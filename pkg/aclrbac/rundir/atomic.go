// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package rundir

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// WriteAtomic writes data to path atomically: it writes to a sibling temp
// file with the requested mode, fsyncs it, then renames it over path. A
// concurrent reader of path therefore sees either the previous complete
// content or the new complete content — never a half-written file — and the
// content is durable across a crash once WriteAtomic returns.
//
// The temp file is created in the same directory as path so the final
// os.Rename is a same-filesystem metadata operation (rename across
// filesystems is not atomic and may even fail). On any failure after the
// temp file is created, it is removed so no .tmp turds accumulate.
//
// Windows note: os.Rename fails if the destination already exists. We
// detect that case and remove the destination before retrying the rename.
// This widens the (already tiny) window where path does not exist, but the
// alternative — leaving a half-written file — is the bug this function
// exists to prevent.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmpName := tmp.Name()

	// Best-effort cleanup if anything below fails before the rename
	// succeeds. cleanup is set to a no-op once the rename lands.
	cleanup := func() { _ = os.Remove(tmpName) }
	defer func() { cleanup() }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp for %s: %w", path, err)
	}
	// fsync the data before the rename so a crash/power-loss after the rename
	// cannot leave a present-but-empty or torn file under path — the run dir is
	// an audit trail and plan.json/acls.json must be durable once written.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp for %s: %w", path, err)
	}
	// CreateTemp makes the file 0o600; apply the caller's mode explicitly
	// so script files end up 0o700 and sensitive artefacts stay 0o600.
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod temp for %s: %w", path, err)
	}

	if err := renameWithRetry(tmpName, path); err != nil {
		return fmt.Errorf("rename temp onto %s: %w", path, err)
	}
	cleanup = func() {}
	return nil
}

// renameWithRetry renames src over dst. On Windows, MoveFileEx fails with a
// sharing-violation ("Access is denied") when another process briefly has
// dst open for reading — a transient condition during concurrent reads of
// run-dir artefacts. We retry a handful of times with a short backoff. On
// the older "destination exists" failure mode we remove dst and retry. On
// non-Windows platforms os.Rename replaces atomically and these branches
// are never exercised.
func renameWithRetry(src, dst string) error {
	// On non-Windows, os.Rename replaces atomically in a single attempt;
	// no retry loop is needed and a failure is a real error.
	if runtime.GOOS != "windows" {
		return os.Rename(src, dst)
	}
	// Windows: a reader holding dst open (even a transient os.ReadFile) can
	// make MoveFileEx return ERROR_ACCESS_DENIED / sharing violation. The
	// window is microseconds for a realistic single reader, but heavy
	// concurrent readers can starve several attempts in a row, so the budget
	// is generous: 50 attempts with a backoff that ramps to and holds at
	// 10ms (~0.5s worst case). The destructive callers (status reading a
	// run dir while plan --revalidate rewrites it) are nowhere near that
	// contended in practice.
	const attempts = 50
	var lastErr error
	for i := 0; i < attempts; i++ {
		err := os.Rename(src, dst)
		if err == nil {
			return nil
		}
		lastErr = err
		// Older "destination exists" failure mode: remove dst and retry now.
		if os.IsExist(err) {
			if rmErr := os.Remove(dst); rmErr == nil {
				continue
			}
		}
		// Sharing violation / access denied: back off briefly and retry.
		backoff := time.Duration(i+1) * time.Millisecond
		if backoff > 10*time.Millisecond {
			backoff = 10 * time.Millisecond
		}
		time.Sleep(backoff)
	}
	return lastErr
}
