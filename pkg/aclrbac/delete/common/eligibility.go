// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package common

import (
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

// EligibilityInputs feed EligibleACLs.
type EligibilityInputs struct {
	Plan       types.Plan
	Verify     []verify.Result
	Principals []string // --principal filter (empty = all)
}

// EligibleACLs returns the source ACL IDs eligible for deletion under the
// rules in spec §4.3 (and §4.4 for DENY removal — DENY callers further
// restrict by deny_analysis status).
//
// Effective-mode verify produces one [verify.Result] per (binding,
// source_acl_id) pair, so eligibility MUST be evaluated at that grain.
// Collapsing to one status per binding and then emitting every
// SourceACLID on the binding would let an EFFECTIVE_OK sibling vouch
// for an EFFECTIVE_MISSING / EFFECTIVE_UNKNOWN row — generating a
// deletion line for an ACL whose effective access was never confirmed.
// That is the safety contract spec §4.3 and README "Step 5" promise
// operators ("never delete an ACL whose effective access isn't OK"),
// so this routine refuses to be clever about it.
//
// Bindings-exist mode produces one Result per binding (no SourceACLID),
// which is coarser by design — the operator opted in by passing
// `--mode bindings-exist` and accepted that grain explicitly. Those
// rows match by BindingID with SourceACLID == 0, and every source ACL
// covered by the binding inherits the binding's status.
func EligibleACLs(in EligibilityInputs) []int {
	// Index per (binding_id, source_acl_id). A SourceACLID of 0 means
	// "applies to every source ACL under this binding" (bindings-exist
	// mode); effective-mode rows always carry the specific id.
	type key struct {
		bindingID   string
		sourceACLID int
	}
	acceptable := func(st verify.Status) bool {
		return st == verify.StatusEffectiveOK || st == verify.StatusBindingExists
	}

	// Collapse duplicate rows for the same (binding_id, source_acl_id)
	// pair with "non-acceptable wins": if verify.json carries the same
	// pair twice — once EFFECTIVE_OK and once EFFECTIVE_MISSING /
	// EFFECTIVE_UNKNOWN — the row must NOT be deleted. A naive
	// last-write-wins map let a trailing OK row silently overwrite an
	// earlier MISSING, generating a deletion line for an ACL whose
	// effective access was never confirmed. We track eligibility as a
	// bool that, once cleared by any non-acceptable row, can never be
	// set back to true regardless of file ordering.
	type pairState struct {
		eligible bool
	}
	stateByPair := map[key]pairState{}
	for _, r := range in.Verify {
		if r.BindingID == "" {
			continue
		}
		k := key{bindingID: r.BindingID, sourceACLID: r.SourceACLID}
		ok := acceptable(r.Status)
		if prev, seen := stateByPair[k]; seen {
			// Non-acceptable wins: stay eligible only if BOTH the prior
			// state and this row are acceptable.
			stateByPair[k] = pairState{eligible: prev.eligible && ok}
			continue
		}
		stateByPair[k] = pairState{eligible: ok}
	}

	principalSet := map[string]bool{}
	for _, p := range in.Principals {
		principalSet[p] = true
	}

	var out []int
	for _, b := range in.Plan.Bindings {
		if len(principalSet) > 0 && !principalSet[b.Principal] {
			continue
		}
		// Binding-grained fallback (bindings-exist mode): if a row with
		// SourceACLID == 0 exists and is acceptable, every source ACL on
		// the binding inherits eligibility. This preserves the
		// pre-bug behaviour for the bindings-exist mode contract.
		bindingLevel, hasBindingLevel := stateByPair[key{bindingID: b.ID, sourceACLID: 0}]
		for _, sid := range b.SourceACLIDs {
			if st, ok := stateByPair[key{bindingID: b.ID, sourceACLID: sid}]; ok {
				if st.eligible {
					out = append(out, sid)
				}
				continue
			}
			if hasBindingLevel && bindingLevel.eligible {
				out = append(out, sid)
			}
		}
	}
	return out
}
