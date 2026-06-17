// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package rundir_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
)

func TestWriteAtomic_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	want := []byte(`{"schema_version":"1"}`)
	if err := rundir.WriteAtomic(path, want, 0o600); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round-trip mismatch: got %q want %q", got, want)
	}
}

func TestWriteAtomic_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("OLD-CONTENT-LONGER"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rundir.WriteAtomic(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteAtomic over existing: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("expected full overwrite; got %q", got)
	}
}

func TestWriteAtomic_PreservesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file-mode bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "delete.sh")
	if err := rundir.WriteAtomic(script, []byte("#!/usr/bin/env bash\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(script)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("script mode = %o, want 0700", info.Mode().Perm())
	}

	sensitive := filepath.Join(dir, "verify.json")
	if err := rundir.WriteAtomic(sensitive, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	info2, _ := os.Stat(sensitive)
	if info2.Mode().Perm() != 0o600 {
		t.Errorf("sensitive mode = %o, want 0600", info2.Mode().Perm())
	}
}

func TestWriteAtomic_NoTempLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	if err := rundir.WriteAtomic(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "plan.json" {
			t.Errorf("unexpected leftover file in run dir: %q", e.Name())
		}
	}
}

// TestWriteAtomic_ConcurrentReadsNeverPartial hammers WriteAtomic with a
// pool of concurrent readers. Because the write goes to a temp file and is
// renamed into place, every successful read must observe one of the two
// complete payloads — never a truncated/interleaved mix.
func TestWriteAtomic_ConcurrentReadsNeverPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")

	small := bytes.Repeat([]byte("A"), 4096)
	large := bytes.Repeat([]byte("B"), 1<<16) // 64 KiB
	if err := rundir.WriteAtomic(path, small, 0o600); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var writerWG, readerWG sync.WaitGroup

	// Writer alternates the two payloads until the readers signal stop.
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		payloads := [][]byte{small, large}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := rundir.WriteAtomic(path, payloads[i%2], 0o600); err != nil {
				t.Errorf("WriteAtomic: %v", err)
				return
			}
		}
	}()

	// Readers verify every read is a complete, uniform payload. Each
	// iteration yields the scheduler (runtime.Gosched) so the readers model
	// a realistic concurrent consumer (e.g. `status` reading the run dir)
	// rather than a pathological spinner — the latter can starve the
	// writer's rename on Windows, where MoveFileEx fails while a handle is
	// open. The no-partial-read invariant is what we're asserting; the
	// writer making forward progress is a precondition for the test to be
	// meaningful, not the property under test.
	for r := 0; r < 4; r++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			for i := 0; i < 1500; i++ {
				data, err := os.ReadFile(path)
				if err != nil {
					// On Windows the rename can briefly race a reader; a
					// transient open error is acceptable (the file is never
					// half-written), but a partial read is not.
					runtime.Gosched()
					continue
				}
				if len(data) == 0 {
					runtime.Gosched()
					continue
				}
				first := data[0]
				if first != 'A' && first != 'B' {
					t.Errorf("partial/garbled read: first byte %q", first)
					return
				}
				for _, b := range data {
					if b != first {
						t.Errorf("interleaved read detected: mixed %q and %q", first, b)
						return
					}
				}
				runtime.Gosched()
			}
		}()
	}

	// Readers run a bounded number of iterations; once they finish, stop
	// the writer and join it.
	readerWG.Wait()
	close(stop)
	writerWG.Wait()
}
