// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package verify

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// effectiveTask is one (binding, source-ACL) lookup unit. Flattening the
// nested plan.Bindings -> SourceACLIDs loop into a flat task slice lets the
// worker pool index result slots directly, preserving serial-path ordering
// in verify.json regardless of completion order.
type effectiveTask struct {
	bindingID string
	principal string
	role      string
	scope     types.Scope
	sid       int
}

// verifyEffective checks per-source-ACL effective permissions. The
// per-source-ACL LookupAllowed call is the parallelizable unit (the hot
// path against a high-latency MDS); calls run concurrently under a
// semaphore of size `parallelism`.
func verifyEffective(cl *mds.Client, plan types.Plan, ops map[int]types.Operation, resources map[int]ResourceRef, prog *Progress, parallelism int) ([]Result, error) {
	parallelism = clampParallelism(parallelism)
	capability, err := mds.ProbeCapability(cl)
	if err != nil {
		// ProbeCapability returns (CapabilityLegacy, nil) for the
		// legitimate "MDS doesn't support the lookup endpoint" case (a
		// 404). A non-nil error therefore means MDS is unreachable or
		// erroring (connection refused, 5xx, 401, ...) — an operational
		// failure. Propagating it (rather than swallowing it and marking
		// every row EFFECTIVE_UNKNOWN) prevents --accept-unknown-verify
		// from silently downgrading an entire run to OK across the board
		// when MDS is simply down.
		return nil, fmt.Errorf("verify: MDS capability probe failed: %w", err)
	}

	// Each Result must carry BindingID alongside SourceACLID. The
	// downstream eligibility check (delete/common/eligibility.go)
	// indexes statuses by BindingID, so an unpopulated field there
	// causes delete-acls to silently see zero eligible ACLs after
	// the recommended `verify --mode effective` flow.
	var tasks []effectiveTask
	for _, b := range plan.Bindings {
		for _, sid := range b.SourceACLIDs {
			tasks = append(tasks, effectiveTask{bindingID: b.ID, principal: b.Principal, role: b.Role, scope: b.Scope, sid: sid})
		}
	}
	total := len(tasks)
	out := make([]Result, total)

	var (
		wg        sync.WaitGroup
		sem       = make(chan struct{}, parallelism)
		processed int64
	)
	for i, t := range tasks {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t effectiveTask) {
			defer wg.Done()
			defer func() { <-sem }()

			res, name := evalEffective(cl, capability, ops, resources, t)
			out[i] = res
			n := atomic.AddInt64(&processed, 1)
			prog.Printf("[%d/%d] %s on %s -> %s (%s)\n", n, total, t.principal, name, t.role, res.Status)
		}(i, t)
	}
	wg.Wait()
	return out, nil
}

// evalEffective performs one effective-permission lookup and returns the
// Result plus the resource name to print in progress output ("<unknown>"
// when the source op/resource is missing).
func evalEffective(cl *mds.Client, capability mds.Capability, ops map[int]types.Operation, resources map[int]ResourceRef, t effectiveTask) (Result, string) {
	op, hasOp := ops[t.sid]
	ref, hasRef := resources[t.sid]
	if !hasOp || !hasRef {
		return Result{BindingID: t.bindingID, SourceACLID: t.sid, Status: StatusEffectiveUnknown, Detail: "missing source op/resource"}, "<unknown>"
	}
	if capability != mds.CapabilityLookup {
		return Result{BindingID: t.bindingID, SourceACLID: t.sid, Status: StatusEffectiveUnknown, Detail: "MDS lookup capability not available"}, ref.Name
	}
	allowed, err := mds.LookupAllowed(cl, t.principal, op, ref.Type, ref.Name, ref.Pattern, t.scope)
	if err != nil {
		return Result{BindingID: t.bindingID, SourceACLID: t.sid, Status: StatusEffectiveUnknown, Detail: err.Error()}, ref.Name
	}
	if allowed {
		return Result{BindingID: t.bindingID, SourceACLID: t.sid, Status: StatusEffectiveOK}, ref.Name
	}
	return Result{BindingID: t.bindingID, SourceACLID: t.sid, Status: StatusEffectiveMissing, Detail: "MDS lookup did not return the expected tuple"}, ref.Name
}
