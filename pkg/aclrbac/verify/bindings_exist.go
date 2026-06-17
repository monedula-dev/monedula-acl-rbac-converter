// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package verify

import (
	"sync"
	"sync/atomic"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// verifyBindingsExist issues one ListBindings call per binding. The calls
// are independent and MDS-latency-bound, so they run concurrently under a
// semaphore of size `parallelism`. Results are written into pre-allocated
// index slots so verify.json ordering is identical to the serial path
// regardless of completion order.
//
// NOTE: grouping bindings by principal (one ListBindings per distinct
// principal instead of per binding) is a known future optimisation; the
// semaphore here is the scaffolding that v0.4 grouping will layer onto.
func verifyBindingsExist(cl *mds.Client, plan types.Plan, prog *Progress, parallelism int) ([]Result, error) {
	parallelism = clampParallelism(parallelism)
	total := len(plan.Bindings)
	out := make([]Result, total)

	var (
		wg        sync.WaitGroup
		sem       = make(chan struct{}, parallelism)
		processed int64
	)
	for i, b := range plan.Bindings {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, b types.Binding) {
			defer wg.Done()
			defer func() { <-sem }()

			existing, err := mds.ListBindings(cl, b.Principal, b.Scope)
			var res Result
			if err != nil {
				// Couldn't ask MDS — operationally distinct from "absent".
				// Report UNKNOWN so a flaky MDS isn't conflated with a
				// genuinely missing binding (the delete gate treats UNKNOWN as
				// not-eligible, the same fail-safe direction).
				res = Result{BindingID: b.ID, Status: StatusBindingUnknown, Detail: err.Error()}
			} else if matched(existing, b) {
				res = Result{BindingID: b.ID, Status: StatusBindingExists}
			} else {
				res = Result{BindingID: b.ID, Status: StatusBindingMissing}
			}
			out[i] = res
			n := atomic.AddInt64(&processed, 1)
			prog.Printf("[%d/%d] %s -> %s (%s)\n", n, total, b.Principal, b.Role, res.Status)
		}(i, b)
	}
	wg.Wait()
	return out, nil
}

func matched(existing []types.Binding, want types.Binding) bool {
	for _, e := range existing {
		if e.Principal != want.Principal {
			continue
		}
		if e.Role != want.Role {
			continue
		}
		if e.Scope != want.Scope {
			continue
		}
		// Every resource pattern the plan binding carries must be present
		// on the existing binding. Containment (not set-equality) is the
		// right relation because MDS aggregates: all bindings a principal
		// holds for one role at one scope come back from ListBindings as a
		// single binding whose ResourcePatterns is the UNION of every
		// pattern granted. The planner, by contrast, emits one binding per
		// source ACL (typically a single pattern), so a principal that
		// reads a topic AND its consumer group — both DeveloperRead — yields
		// two 1-pattern plan bindings that MDS stores as one 2-pattern
		// binding. Set-equality reported both as MISSING even though both
		// patterns are installed.
		//
		// Containment stays safe for the delete gate: a planned binding for
		// (User:alice, DeveloperRead, Topic:payments LITERAL) is only matched
		// by an existing binding that actually carries Topic:payments LITERAL,
		// so an unrelated Topic:orders binding never satisfies it. The match
		// is a multiset subset on (resource_type, name, pattern_type) triples,
		// so ordering doesn't matter and duplicate patterns are honored.
		if !patternsSubset(want.ResourcePatterns, e.ResourcePatterns) {
			continue
		}
		return true
	}
	return false
}

// patternsSubset reports whether every ResourcePattern in want appears in
// have, compared as a multiset on (ResourceType, Name, PatternType). It is
// the containment relation verify needs because MDS returns one binding per
// (principal, role, scope) whose patterns are the union of all grants, while
// the plan carries each source ACL as its own binding.
func patternsSubset(want, have []types.ResourcePattern) bool {
	if len(want) > len(have) {
		return false
	}
	counts := map[types.ResourcePattern]int{}
	for _, p := range have {
		counts[p]++
	}
	for _, p := range want {
		counts[p]--
		if counts[p] < 0 {
			return false
		}
	}
	return true
}
