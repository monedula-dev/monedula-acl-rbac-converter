// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package rundir_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
)

// TestLock_ConcurrentAcquireExactlyOneWins pins the mutual-exclusion invariant
// the lock exists to provide: when many callers race to acquire a fresh run
// dir, exactly one succeeds. The old read-check-write acquire (no
// O_CREATE|O_EXCL) let several racers all observe "no lockfile" and all write
// it, so more than one "held" the lock that serializes destructive operations.
func TestLock_ConcurrentAcquireExactlyOneWins(t *testing.T) {
	dir := t.TempDir()
	const n = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var locks []*rundir.Lock
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if l, err := rundir.Acquire(dir, "apply"); err == nil {
				mu.Lock()
				locks = append(locks, l)
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if len(locks) != 1 {
		t.Errorf("expected exactly 1 successful acquire among %d racers, got %d", n, len(locks))
	}
	for _, l := range locks {
		_ = l.Release()
	}
}

func TestLock_CreatesAndReleases(t *testing.T) {
	dir := t.TempDir()
	lock, err := rundir.Acquire(dir, "apply")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".lock")); err != nil {
		t.Errorf("lockfile not created: %v", err)
	}

	if err := lock.Release(); err != nil {
		t.Errorf("release: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".lock")); !os.IsNotExist(err) {
		t.Errorf("lockfile should be removed after release; got %v", err)
	}
}

// TestLock_ReleaseDoesNotRemoveReacquiredLock pins that Release only removes
// the lockfile if it still carries this lock's token. If another holder
// force-unlocked and took the lock, the original Release must leave their lock
// in place rather than opening the run dir to a third process mid-run.
func TestLock_ReleaseDoesNotRemoveReacquiredLock(t *testing.T) {
	dir := t.TempDir()
	a, err := rundir.Acquire(dir, "apply")
	if err != nil {
		t.Fatalf("acquire A: %v", err)
	}
	// Someone force-unlocks and re-takes the lock (new token).
	b, err := rundir.AcquireForceUnlock(dir, "delete-acls")
	if err != nil {
		t.Fatalf("force-acquire B: %v", err)
	}
	// A's Release must NOT remove B's lock.
	if err := a.Release(); err != nil {
		t.Fatalf("release A: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".lock")); err != nil {
		t.Errorf("A.Release removed B's lock; lockfile should still exist: %v", err)
	}
	// B can still release its own lock.
	if err := b.Release(); err != nil {
		t.Fatalf("release B: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".lock")); !os.IsNotExist(err) {
		t.Errorf("B.Release should have removed the lockfile; got %v", err)
	}
}

func TestLock_FailsWhenHeldByLivePID(t *testing.T) {
	dir := t.TempDir()
	first, err := rundir.Acquire(dir, "apply")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer first.Release()

	_, err = rundir.Acquire(dir, "delete-acls")
	if err == nil {
		t.Fatal("expected error when lock held by live PID")
	}
	msg := err.Error()
	if !strings.Contains(msg, "lock held") {
		t.Errorf("error should mention lock held; got: %v", err)
	}
	// The original holder's cmd ("apply") must appear in the error so
	// the operator knows which command to look for. (#1 from the
	// sixth review.)
	if !strings.Contains(msg, `"apply"`) {
		t.Errorf("error should quote the holder cmd; got: %v", err)
	}
}

// TestLock_BodyContainsAllSpecFields asserts the .lock file body has
// pid/hostname/cmd/started fields per spec section 4.2. A refactor that
// drops any of these would silently produce un-parseable lockfiles;
// catching the regression at the schema level prevents that.
func TestLock_BodyContainsAllSpecFields(t *testing.T) {
	dir := t.TempDir()
	lock, err := rundir.Acquire(dir, "delete-deny-acls")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer lock.Release()

	body, err := os.ReadFile(filepath.Join(dir, ".lock"))
	if err != nil {
		t.Fatalf("read lock: %v", err)
	}
	s := string(body)

	for _, key := range []string{"pid=", "hostname=", "cmd=", "started="} {
		if !strings.Contains(s, key) {
			t.Errorf("lockfile body missing %s field:\n%s", key, s)
		}
	}
	if !strings.Contains(s, "cmd=delete-deny-acls") {
		t.Errorf("cmd field should contain the command name passed to Acquire; got:\n%s", s)
	}
}

func TestLock_StalePIDIsReplaceableWithForceUnlock(t *testing.T) {
	dir := t.TempDir()
	// Write a stale lockfile with a PID that's almost certainly not alive.
	stale := []byte("pid=99999999\nhostname=staleserver\ncmd=apply\nstarted=2020-01-01T00:00:00Z\n")
	if err := os.WriteFile(filepath.Join(dir, ".lock"), stale, 0o644); err != nil {
		t.Fatalf("write stale: %v", err)
	}

	// Without force-unlock, it should fail.
	_, err := rundir.Acquire(dir, "apply")
	if err == nil {
		t.Fatal("expected error for stale lockfile without force-unlock")
	}

	// With force-unlock, it should succeed.
	lock, err := rundir.AcquireForceUnlock(dir, "apply")
	if err != nil {
		t.Fatalf("acquire with force-unlock: %v", err)
	}
	defer lock.Release()
}
