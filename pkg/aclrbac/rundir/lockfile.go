// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package rundir

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Lock represents an acquired run-directory lockfile.
type Lock struct {
	path  string
	token string // per-acquire random token, written into the lockfile body
}

// Release deletes the lockfile, but only if it still carries this lock's
// token — so if another operator force-unlocked and took the lock, this
// Release does not remove THEIR lock. Safe to call on a nil receiver (no-op)
// so callers can `defer lock.Release()` without nil checks.
func (l *Lock) Release() error {
	if l == nil {
		return nil
	}
	data, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already gone
		}
		return fmt.Errorf("read lock for release: %w", err)
	}
	if _, _, _, tok := parseLock(data); tok != l.token {
		// The lockfile is no longer ours (force-unlocked and re-taken). Leave
		// it for its current owner.
		return nil
	}
	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove lock: %w", err)
	}
	return nil
}

// Acquire creates `.lock` in dir with this process's identity. Returns an
// error if a lockfile already exists and its recorded PID is alive on the
// recorded host.
func Acquire(dir, cmd string) (*Lock, error) {
	return acquire(dir, cmd, false)
}

// AcquireForceUnlock is Acquire with the --force-unlock semantics from
// §4.2: an existing lockfile is removed before the new one is written,
// regardless of whether its PID looks alive.
func AcquireForceUnlock(dir, cmd string) (*Lock, error) {
	return acquire(dir, cmd, true)
}

func acquire(dir, cmd string, force bool) (*Lock, error) {
	path := filepath.Join(dir, ".lock")
	// Two attempts at most: the first may lose to an existing lock; if that
	// lock is stale (or --force-unlock) we remove it and retry the exclusive
	// create exactly once. The O_CREATE|O_EXCL create is what makes acquisition
	// atomic — only one concurrent caller can win the create, so the lock
	// genuinely serializes destructive operations.
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			host, _ := os.Hostname()
			token := randomToken()
			body := fmt.Sprintf(
				"pid=%d\nhostname=%s\ncmd=%s\nstarted=%s\ntoken=%s\n",
				os.Getpid(), host, cmd, time.Now().UTC().Format(time.RFC3339), token,
			)
			if _, werr := f.WriteString(body); werr != nil {
				_ = f.Close()
				return nil, fmt.Errorf("write lock: %w", werr)
			}
			if cerr := f.Close(); cerr != nil {
				return nil, fmt.Errorf("write lock: %w", cerr)
			}
			return &Lock{path: path, token: token}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create lock: %w", err)
		}

		// The lock already exists — inspect it.
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			if errors.Is(rerr, os.ErrNotExist) {
				continue // it vanished between create and read; retry the create
			}
			return nil, fmt.Errorf("read lock: %w", rerr)
		}
		pid, host, cmdHeld, _ := parseLock(data)
		alive := pidAliveOnHost(pid, host)
		held := fmt.Sprintf("pid %d", pid)
		if cmdHeld != "" {
			held = fmt.Sprintf("pid %d running %q", pid, cmdHeld)
		}
		if alive && !force {
			return nil, fmt.Errorf(
				"lock held by %s on %s (lockfile: %s); use --force-unlock if you are sure that process is gone",
				held, host, path,
			)
		}
		if !alive && !force {
			return nil, fmt.Errorf(
				"stale lockfile at %s (%s on %s appears dead); re-run with --force-unlock",
				path, held, host,
			)
		}
		// force, or stale under force: remove and retry the exclusive create.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("remove stale lock: %w", err)
		}
	}
	return nil, fmt.Errorf("could not acquire lock at %s after retry", path)
}

func parseLock(data []byte) (pid int, host, cmd, token string) {
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "pid="):
			pid, _ = strconv.Atoi(strings.TrimPrefix(line, "pid="))
		case strings.HasPrefix(line, "hostname="):
			host = strings.TrimPrefix(line, "hostname=")
		case strings.HasPrefix(line, "cmd="):
			cmd = strings.TrimPrefix(line, "cmd=")
		case strings.HasPrefix(line, "token="):
			token = strings.TrimPrefix(line, "token=")
		}
	}
	return pid, host, cmd, token
}

// randomToken returns a 128-bit hex token identifying a specific lock
// acquisition, so Release can verify it still owns the lockfile.
func randomToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is effectively fatal on supported platforms;
		// fall back to a pid/time-derived value so we never write an empty
		// token (which would make Release match a tokenless lock).
		return fmt.Sprintf("fallback-%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// pidAliveOnHost returns true only when the recorded host matches the
// current hostname AND a process with that PID exists. A non-matching host
// is always reported as "not alive" because we cannot probe a different
// machine. The same process is always treated as alive (handles the
// re-entrant lock check).
func pidAliveOnHost(pid int, host string) bool {
	if pid <= 0 {
		return false
	}
	thisHost, _ := os.Hostname()
	if host != "" && host != thisHost {
		return false
	}
	// Our own PID is trivially alive.
	if pid == os.Getpid() {
		return true
	}
	return processAlive(pid)
}
