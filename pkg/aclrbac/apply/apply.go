// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package apply executes a RoleBindingPlan against MDS. It is idempotent:
// for each binding it first lists existing bindings; only creates the
// missing ones. Records every call to runs/<ts>/apply.log.
package apply

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Options bundles everything Run/DryRun need. Constructed by M8's CLI.
type Options struct {
	RunDir      string
	PlanPath    string
	Client      *mds.Client
	Parallelism int // default 4
	ForceUnlock bool
	Progress    *Progress // optional; non-nil enables per-binding progress output

	// SummaryWriter, if non-nil, receives a structured summary after
	// Run completes. The CLI sets this to os.Stdout when the user
	// passes --format. The format defaults to FormatText if
	// SummaryFormat is empty.
	SummaryWriter io.Writer
	SummaryFormat Format
}

// Run applies a plan to MDS. Requires --confirm to be set by the CLI; this
// function does not enforce that gate (the CLI does, before calling).
func Run(opts Options) error {
	plan, lock, err := prepare(opts)
	if err != nil {
		return err
	}
	defer lock.Release()

	logF, err := os.OpenFile(filepath.Join(opts.RunDir, "apply.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open apply.log: %w", err)
	}
	defer logF.Close()

	prog := opts.Progress
	if prog == nil {
		prog = NewProgress(false)
	}
	// Mirror verify.clampParallelism: <=0 → default 4; above the soft cap
	// stays at the cap. Without the cap, `--apply-parallelism 5000` would
	// spawn 5000 goroutines and 5000 concurrent POSTs at MDS — well past any
	// useful concurrency, just spammier on a flaky server. 64 matches verify
	// and is the same "operator-friendly soft cap" rationale: clamp rather
	// than error so an over-eager --apply-parallelism never fails the run.
	const applyMaxParallelism = 64
	parallelism := opts.Parallelism
	if parallelism <= 0 {
		parallelism = 4
	}
	if parallelism > applyMaxParallelism {
		parallelism = applyMaxParallelism
	}

	total := int64(len(plan.Bindings))
	var (
		processed int64
		mu        sync.Mutex
		wg        sync.WaitGroup
		errCh     = make(chan error, len(plan.Bindings))
		results   = make([]BindingResult, 0, len(plan.Bindings))
	)

	// record writes one apply.log line AND appends one BindingResult
	// to the summary slice under the shared mu. Keeping both writes
	// inside a single critical section means the log and the summary
	// stay consistent — every line in apply.log has a matching row in
	// the summary, and ordering between bindings is the same.
	record := func(r BindingResult, logFormat string, args ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(logF, "%s\t%s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(logFormat, args...))
		results = append(results, r)
	}

	sem := make(chan struct{}, parallelism)
	for _, b := range plan.Bindings {
		if b.Action == types.ActionSkipExists {
			n := atomic.AddInt64(&processed, 1)
			record(
				BindingResult{BindingID: b.ID, Principal: b.Principal, Role: b.Role, Status: StatusSkipExists},
				"SKIP %s already exists", b.ID,
			)
			prog.Printf("[%d/%d] %s -> %s (skip)\n", n, total, b.Principal, b.Role)
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(b types.Binding) {
			defer wg.Done()
			defer func() { <-sem }()

			existing, err := mds.ListBindings(opts.Client, b.Principal, b.Scope)
			if err != nil {
				errCh <- fmt.Errorf("list %s: %w", b.Principal, err)
				n := atomic.AddInt64(&processed, 1)
				record(
					BindingResult{BindingID: b.ID, Principal: b.Principal, Role: b.Role, Status: StatusFailed, Error: fmt.Sprintf("list: %v", err)},
					"FAIL %s: list: %v", b.ID, err,
				)
				prog.Printf("[%d/%d] %s -> %s (failed)\n", n, total, b.Principal, b.Role)
				return
			}
			if alreadyHas(existing, b) {
				n := atomic.AddInt64(&processed, 1)
				record(
					BindingResult{BindingID: b.ID, Principal: b.Principal, Role: b.Role, Status: StatusSkipExists},
					"SKIP %s already exists (verified)", b.ID,
				)
				prog.Printf("[%d/%d] %s -> %s (skip)\n", n, total, b.Principal, b.Role)
				return
			}
			if err := mds.CreateRoleBinding(opts.Client, b); err != nil {
				errCh <- fmt.Errorf("create %s: %w", b.ID, err)
				n := atomic.AddInt64(&processed, 1)
				record(
					BindingResult{BindingID: b.ID, Principal: b.Principal, Role: b.Role, Status: StatusFailed, Error: err.Error()},
					"FAIL %s: %v", b.ID, err,
				)
				prog.Printf("[%d/%d] %s -> %s (failed)\n", n, total, b.Principal, b.Role)
				return
			}
			n := atomic.AddInt64(&processed, 1)
			record(
				BindingResult{BindingID: b.ID, Principal: b.Principal, Role: b.Role, Status: StatusCreated},
				"CREATE %s %s -> %s", b.ID, b.Principal, b.Role,
			)
			prog.Printf("[%d/%d] %s -> %s (create)\n", n, total, b.Principal, b.Role)
		}(b)
	}
	wg.Wait()
	close(errCh)

	var firstErr error
	for e := range errCh {
		if firstErr == nil {
			firstErr = e
		}
	}

	// Render summary regardless of whether we hit failures — operators
	// rely on the per-binding outcomes (including FAILED rows) when
	// triaging a partial run. The error returned below is reported by
	// the CLI as a non-zero exit code; the summary informs why.
	if opts.SummaryWriter != nil {
		sum := Summary{Bindings: results}
		format := opts.SummaryFormat
		if format == "" {
			format = FormatText
		}
		var sumErr error
		switch format {
		case FormatJSON:
			sumErr = sum.WriteJSON(opts.SummaryWriter)
		default:
			sumErr = sum.WriteText(opts.SummaryWriter)
		}
		if sumErr != nil {
			if firstErr != nil {
				// Preserve the original failure but surface the summary
				// emit error too — it's a real bug if stdout went away
				// mid-run.
				return fmt.Errorf("apply failed: %v; additionally: write summary: %w", firstErr, sumErr)
			}
			return fmt.Errorf("write summary: %w", sumErr)
		}
	}

	if firstErr != nil {
		return firstErr
	}
	return nil
}

func prepare(opts Options) (types.Plan, *rundir.Lock, error) {
	// Acquire the run-dir lock BEFORE verifying/reading the plan so the
	// checksum-verify and the read happen under the lock — otherwise a
	// concurrent plan regeneration could rewrite plan.json between
	// VerifyChecksum and ReadPlan and apply would execute bytes the checksum
	// never vouched for.
	var (
		lock *rundir.Lock
		err  error
	)
	if opts.ForceUnlock {
		lock, err = rundir.AcquireForceUnlock(opts.RunDir, "apply")
	} else {
		lock, err = rundir.Acquire(opts.RunDir, "apply")
	}
	if err != nil {
		return types.Plan{}, nil, err
	}
	if err := rundir.VerifyChecksum(opts.PlanPath); err != nil {
		_ = lock.Release()
		return types.Plan{}, nil, fmt.Errorf("stale plan: %w", err)
	}
	plan, err := rundir.ReadPlan(opts.PlanPath)
	if err != nil {
		_ = lock.Release()
		return types.Plan{}, nil, err
	}
	return plan, lock, nil
}

func alreadyHas(existing []types.Binding, want types.Binding) bool {
	for _, e := range existing {
		if e.Principal != want.Principal || e.Role != want.Role {
			continue
		}
		if e.Scope != want.Scope {
			continue
		}
		if patternsEqual(e.ResourcePatterns, want.ResourcePatterns) {
			return true
		}
	}
	return false
}

func patternsEqual(a, b []types.ResourcePattern) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[types.ResourcePattern]int{}
	for _, p := range a {
		count[p]++
	}
	for _, p := range b {
		if count[p] == 0 {
			return false
		}
		count[p]--
	}
	return true
}
