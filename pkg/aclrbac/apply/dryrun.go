// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package apply

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// DryRun previews the MDS calls Run() would make, without mutating anything.
// Writes runs/<ts>/would-apply.log with the planned operations and, when
// opts.SummaryWriter is set, emits a one-line summary in the same shape
// as production Run — prefixed "apply (dry-run):" — so CI scripts that
// branch on the apply summary keep working in dry-run mode.
//
// FAILED is never emitted by DryRun: we don't attempt POSTs. List
// failures degrade to WOULD_CREATE (we can't prove the binding exists,
// so we assume it doesn't) and log the list error in would-apply.log
// for the operator to triage.
func DryRun(opts Options) error {
	// Hold the run-dir lock around the checksum-verify and read, both to
	// serialize against a concurrent apply/plan-regeneration and to close the
	// verify/read TOCTOU window (same reasoning as prepare()).
	var (
		lock *rundir.Lock
		err  error
	)
	if opts.ForceUnlock {
		lock, err = rundir.AcquireForceUnlock(opts.RunDir, "apply-dry-run")
	} else {
		lock, err = rundir.Acquire(opts.RunDir, "apply-dry-run")
	}
	if err != nil {
		return err
	}
	defer lock.Release()

	if err := rundir.VerifyChecksum(opts.PlanPath); err != nil {
		return err
	}
	plan, err := rundir.ReadPlan(opts.PlanPath)
	if err != nil {
		return err
	}

	logPath := filepath.Join(opts.RunDir, "would-apply.log")
	f, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", logPath, err)
	}
	defer f.Close()

	results := make([]BindingResult, 0, len(plan.Bindings))
	for _, b := range plan.Bindings {
		if b.Action == types.ActionSkipExists {
			fmt.Fprintf(f, "SKIP %s already in plan\n", b.ID)
			results = append(results, BindingResult{BindingID: b.ID, Principal: b.Principal, Role: b.Role, Status: StatusWouldSkip})
			continue
		}
		existing, err := mds.ListBindings(opts.Client, b.Principal, b.Scope)
		if err != nil {
			fmt.Fprintf(f, "UNKNOWN %s: list failed: %v\n", b.ID, err)
			// We can't prove the binding already exists; assume the
			// real apply would attempt creation.
			results = append(results, BindingResult{BindingID: b.ID, Principal: b.Principal, Role: b.Role, Status: StatusWouldCreate})
			continue
		}
		if alreadyHas(existing, b) {
			fmt.Fprintf(f, "SKIP %s (already exists in MDS)\n", b.ID)
			results = append(results, BindingResult{BindingID: b.ID, Principal: b.Principal, Role: b.Role, Status: StatusWouldSkip})
			continue
		}
		body, _ := json.Marshal(struct {
			Scope            types.Scope             `json:"scope"`
			ResourcePatterns []types.ResourcePattern `json:"resource_patterns"`
		}{b.Scope, b.ResourcePatterns})
		fmt.Fprintf(f, "WOULD POST /security/1.0/principals/%s/roles/%s/bindings\nBODY %s\n",
			b.Principal, b.Role, body)
		results = append(results, BindingResult{BindingID: b.ID, Principal: b.Principal, Role: b.Role, Status: StatusWouldCreate})
	}

	if opts.SummaryWriter != nil {
		sum := Summary{Bindings: results}
		format := opts.SummaryFormat
		if format == "" {
			format = FormatText
		}
		switch format {
		case FormatJSON:
			if err := sum.WriteJSON(opts.SummaryWriter); err != nil {
				return fmt.Errorf("write summary: %w", err)
			}
		default:
			if err := sum.WriteText(opts.SummaryWriter); err != nil {
				return fmt.Errorf("write summary: %w", err)
			}
		}
	}
	return nil
}
