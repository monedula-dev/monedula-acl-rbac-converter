// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan_test

import (
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestDeny_SafeToRemove(t *testing.T) {
	// Allow Read on orders for alice; Deny Read on secrets for alice.
	// Nothing grants alice Read on secrets, so removing the DENY is safe.
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				{ID: 99, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets", PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}

	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.DenyAnalysis) != 1 {
		t.Fatalf("expected 1 deny entry; got %d", len(p.DenyAnalysis))
	}
	if p.DenyAnalysis[0].Status != types.DenySafeToRemove {
		t.Errorf("status: got %q, want SAFE_TO_REMOVE", p.DenyAnalysis[0].Status)
	}
}

func TestDeny_WouldGrantAccess_PrefixedCovers(t *testing.T) {
	// Allow Read+Describe on Topic:* (prefixed) for alice; Deny Read on secrets.
	// Removing the DENY would let alice read secrets via the prefix.
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secret-prefix", PatternType: types.PatternPrefixed, PermissionType: types.PermissionAllow},
				{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "secret-prefix", PatternType: types.PatternPrefixed, PermissionType: types.PermissionAllow},
				{ID: 99, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secret-prefix-leaked", PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}

	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if p.DenyAnalysis[0].Status != types.DenyWouldGrantAccess {
		t.Errorf("status: got %q, want WOULD_GRANT_ACCESS", p.DenyAnalysis[0].Status)
	}
	if p.DenyAnalysis[0].CoveringRule == "" {
		t.Errorf("expected non-empty covering_rule")
	}
}

// TestDeny_WouldGrantAccess_LiteralInsidePrefixedDeny is the regression guard
// for the access-grant blocker: a PREFIXED DENY denies a whole namespace, so
// a LITERAL Allow for a resource INSIDE that namespace means removing the DENY
// grants access. The old patternCovers only checked "does the Allow cover the
// DENY's literal name", so it classified this SAFE_TO_REMOVE and would have
// silently granted access on removal.
func TestDeny_WouldGrantAccess_LiteralInsidePrefixedDeny(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				// Allow alice Read on the specific topic secret-prod (LITERAL).
				{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secret-prod", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				// Deny alice Read on the whole secret-* namespace (PREFIXED).
				{ID: 99, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secret-", PatternType: types.PatternPrefixed, PermissionType: types.PermissionDeny},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.DenyAnalysis) != 1 {
		t.Fatalf("expected 1 deny entry; got %d", len(p.DenyAnalysis))
	}
	if p.DenyAnalysis[0].Status != types.DenyWouldGrantAccess {
		t.Errorf("status: got %q, want WOULD_GRANT_ACCESS (removing the PREFIXED DENY would expose the LITERAL Allow on secret-prod)", p.DenyAnalysis[0].Status)
	}
}

// TestDeny_WouldGrantAccess_NarrowerPrefixInsidePrefixedDeny covers the other
// missed shape: an Allow with a NARROWER prefix nested inside the denied prefix.
func TestDeny_WouldGrantAccess_NarrowerPrefixInsidePrefixedDeny(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secret-prod-", PatternType: types.PatternPrefixed, PermissionType: types.PermissionAllow},
				{ID: 99, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secret-", PatternType: types.PatternPrefixed, PermissionType: types.PermissionDeny},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if p.DenyAnalysis[0].Status != types.DenyWouldGrantAccess {
		t.Errorf("status: got %q, want WOULD_GRANT_ACCESS (secret-prod-* nested in denied secret-*)", p.DenyAnalysis[0].Status)
	}
}

// TestDeny_AllOperation_WouldGrantAccess is the regression guard for the
// access-grant blocker on DENY rows whose operation is `All`. Normalize never
// expands the operation of a raw DENY row, so a `DENY All` row keeps
// Operation=All. Removing it exposes every surviving Allow on the overlapping
// resource — here an Allow Read on the same topic — so it must be
// WOULD_GRANT_ACCESS, never SAFE_TO_REMOVE.
func TestDeny_AllOperation_WouldGrantAccess(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				{ID: 99, Principal: "User:alice", Host: "*", Operation: types.OpAll, ResourceType: types.ResourceTopic, ResourceName: "secrets", PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var denyEntry *types.DenyAnalysisEntry
	for i := range p.DenyAnalysis {
		if p.DenyAnalysis[i].SourceACLID == 99 {
			denyEntry = &p.DenyAnalysis[i]
		}
	}
	if denyEntry == nil {
		t.Fatal("no deny_analysis entry for the DENY All row (acl_id=99)")
	}
	if denyEntry.Status == types.DenySafeToRemove {
		t.Fatal("SECURITY: a DENY All overlapping a surviving Allow must never be SAFE_TO_REMOVE")
	}
	if denyEntry.Status != types.DenyWouldGrantAccess {
		t.Errorf("status: got %q, want WOULD_GRANT_ACCESS", denyEntry.Status)
	}
}

// TestDeny_ImpliedDescribe_WouldGrantAccess pins Kafka's operation-implication
// rule: an Allow for Read/Write/Delete/Alter implies Describe. So a DENY
// Describe overlapping a surviving Allow Read grants Describe on removal and
// must be WOULD_GRANT_ACCESS — exact op equality alone misses it.
func TestDeny_ImpliedDescribe_WouldGrantAccess(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				{ID: 99, Principal: "User:alice", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var e *types.DenyAnalysisEntry
	for i := range p.DenyAnalysis {
		if p.DenyAnalysis[i].SourceACLID == 99 {
			e = &p.DenyAnalysis[i]
		}
	}
	if e == nil {
		t.Fatal("no deny_analysis entry for acl_id=99")
	}
	if e.Status != types.DenyWouldGrantAccess {
		t.Errorf("SECURITY: Allow Read implies Describe; DENY Describe must be WOULD_GRANT_ACCESS, got %q", e.Status)
	}
}

// TestDeny_WildcardAllowCoversConcreteDeny pins that an Allow for a wildcard
// principal (User:*) covers a concrete-principal DENY (User:alice) on the
// overlapping resource. Removing alice's DENY while the User:* Allow survives
// grants alice access, so it must be WOULD_GRANT_ACCESS — strict principal
// equality misses the wildcard Allow.
func TestDeny_WildcardAllowCoversConcreteDeny(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:*", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				{ID: 99, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets", PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var e *types.DenyAnalysisEntry
	for i := range p.DenyAnalysis {
		if p.DenyAnalysis[i].SourceACLID == 99 {
			e = &p.DenyAnalysis[i]
		}
	}
	if e == nil {
		t.Fatal("no deny_analysis entry for acl_id=99")
	}
	if e.Status == types.DenySafeToRemove {
		t.Fatal("SECURITY: a concrete DENY covered by a wildcard Allow must never be SAFE_TO_REMOVE")
	}
	if e.Status != types.DenyWouldGrantAccess {
		t.Errorf("status: got %q, want WOULD_GRANT_ACCESS", e.Status)
	}
}

// TestDeny_UnrelatedWildcardAllowTypeDoesNotCover guards against over-matching:
// a Group:* Allow must NOT cover a User:alice DENY (different principal type),
// so with no other grant the DENY stays SAFE_TO_REMOVE.
func TestDeny_UnrelatedWildcardAllowTypeDoesNotCover(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "Group:*", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				{ID: 99, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets", PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for i := range p.DenyAnalysis {
		if p.DenyAnalysis[i].SourceACLID == 99 && p.DenyAnalysis[i].Status != types.DenySafeToRemove {
			t.Errorf("Group:* Allow must not cover a User:alice DENY; got %q", p.DenyAnalysis[i].Status)
		}
	}
}

func TestDeny_WildcardPrincipalUnknown(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{{
				ID: 99, Principal: "User:*", Host: "*", Operation: types.OpRead,
				ResourceType: types.ResourceTopic, ResourceName: "secrets",
				PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny,
			}},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}

	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if p.DenyAnalysis[0].Status != types.DenyUnknown {
		t.Errorf("wildcard principal should yield UNKNOWN; got %q", p.DenyAnalysis[0].Status)
	}
}

// TestDeny_WildcardPrincipalUnknownEvenWithMatchingAllow is the
// negative-security assertion: the wildcard-principal short-circuit must
// take precedence over the overlap check. A DENY on User:* that ALSO has a
// concrete overlapping Allow for the same principal pattern must classify
// UNKNOWN — never SAFE_TO_REMOVE. Without the short-circuit, the resource
// overlap could be evaluated against a single principal and the analysis
// could declare the DENY removable, silently granting access to every
// principal the wildcard covers. The only safe answer for an unresolvable
// wildcard is UNKNOWN (requires human review).
func TestDeny_WildcardPrincipalUnknownEvenWithMatchingAllow(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				// A concrete Allow that, for a non-wildcard principal, would
				// make the DENY WOULD_GRANT_ACCESS.
				{ID: 1, Principal: "User:*", Host: "*", Operation: types.OpRead,
					ResourceType: types.ResourceTopic, ResourceName: "secret-",
					PatternType: types.PatternPrefixed, PermissionType: types.PermissionAllow},
				// The wildcard DENY overlapping that Allow.
				{ID: 2, Principal: "User:*", Host: "*", Operation: types.OpRead,
					ResourceType: types.ResourceTopic, ResourceName: "secret-prod",
					PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}

	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var denyEntry *types.DenyAnalysisEntry
	for i := range p.DenyAnalysis {
		if p.DenyAnalysis[i].SourceACLID == 2 {
			denyEntry = &p.DenyAnalysis[i]
		}
	}
	if denyEntry == nil {
		t.Fatal("no deny_analysis entry for the wildcard DENY (acl_id=2)")
	}
	if denyEntry.Status == types.DenySafeToRemove {
		t.Fatal("SECURITY: a wildcard-principal DENY must never be SAFE_TO_REMOVE")
	}
	if denyEntry.Status != types.DenyUnknown {
		t.Errorf("wildcard DENY must be UNKNOWN regardless of a matching Allow; got %q", denyEntry.Status)
	}
}

// TestDeny_GroupWildcardPrincipalUnknown pins that the wildcard guard
// matches the ":*" suffix generically — a Group:* DENY is just as
// unanalysable as User:* and must be UNKNOWN, not SAFE_TO_REMOVE.
func TestDeny_GroupWildcardPrincipalUnknown(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{{
				ID: 7, Principal: "Group:*", Host: "*", Operation: types.OpRead,
				ResourceType: types.ResourceTopic, ResourceName: "secrets",
				PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny,
			}},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if p.DenyAnalysis[0].Status != types.DenyUnknown {
		t.Errorf("Group:* DENY should yield UNKNOWN; got %q", p.DenyAnalysis[0].Status)
	}
}

// TestDeny_BareWildcardPrincipalUnknown is the P2 regression guard: a DENY
// whose principal is the bare "*" (no type prefix — some principal builders
// emit it raw) must classify UNKNOWN, exactly like "User:*"/"Group:*". The
// previous predicate caught only ":*", so a bare "*" DENY slipped through and
// could be classified SAFE_TO_REMOVE — the planner half of the bug the shared
// types.IsWildcardPrincipal closes.
func TestDeny_BareWildcardPrincipalUnknown(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{{
				ID: 5, Principal: "*", Host: "*", Operation: types.OpRead,
				ResourceType: types.ResourceTopic, ResourceName: "secrets",
				PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny,
			}},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if p.DenyAnalysis[0].Status != types.DenyUnknown {
		t.Errorf("bare \"*\" DENY should yield UNKNOWN; got %q", p.DenyAnalysis[0].Status)
	}
}
