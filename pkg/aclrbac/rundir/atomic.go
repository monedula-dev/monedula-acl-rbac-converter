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
// Windows note: the final rename cannot replace path while another process
// holds it open, so it is retried under a wall-clock budget rather than
// attempted once. See renameWithRetry.
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

// renameBudget bounds how long renameWithRetry waits for a Windows reader
// to release the destination. Generous because the failure it prevents is a
// hard error on an audit-trail write, and cheap because a rename that can
// succeed does so on the first attempt; only a genuinely held handle waits.
const renameBudget = 5 * time.Second

// renameWithRetry renames src over dst. On Windows this needs a retry loop:
// os.Open takes FILE_SHARE_READ|FILE_SHARE_WRITE but not FILE_SHARE_DELETE,
// so MoveFileEx cannot replace dst while any reader holds it open and fails
// with ERROR_ACCESS_DENIED ("Access is denied") for the *whole* duration of
// that reader's open — this is mutual exclusion against readers, not a
// microsecond interleaving race. A reader that re-opens dst in a tight loop
// can therefore starve a fixed number of attempts, so the budget is
// wall-clock (renameBudget) rather than an attempt count: a slow or loaded
// machine gets proportionally more chances instead of the same handful.
// On the older "destination exists" failure mode we remove dst and retry.
// On non-Windows platforms os.Rename replaces atomically and these branches
// are never exercised.
func renameWithRetry(src, dst string) error {
	if runtime.GOOS != "windows" {
		return os.Rename(src, dst)
	}

	start := time.Now()
	const maxBackoff = 10 * time.Millisecond
	backoff := time.Millisecond
	for {
		err := os.Rename(src, dst)
		if err == nil {
			return nil
		}
		if elapsed := time.Since(start); elapsed >= renameBudget {
			// Name the wait in the error: an operator seeing this has a
			// process holding the artefact open (an editor, a virus
			// scanner, another monedula-acl-rbac run), not a flaky disk.
			return fmt.Errorf("after waiting %s for another process to release it: %w", elapsed.Round(time.Millisecond), err)
		}
		// Older "destination exists" failure mode: remove dst and retry
		// immediately, without spending the backoff.
		if os.IsExist(err) {
			if rmErr := os.Remove(dst); rmErr == nil {
				continue
			}
		}
		time.Sleep(backoff)
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}
