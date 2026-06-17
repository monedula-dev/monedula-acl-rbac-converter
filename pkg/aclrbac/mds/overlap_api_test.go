// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

var overlapScope = types.Scope{KafkaCluster: "lkc-kafka01"}

// grantFake serves the two endpoints PrincipalGrantOverlaps uses: the
// principal-resources lookup (role "R" -> one pattern) and role "R"'s
// definition (granting op on rt). Together they expand to a single grant
// (op, rt, name, pattern) for the principal.
func grantFake(rt, name, pattern, op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/security/1.0/roles/"):
			_, _ = w.Write([]byte(`{"name":"R","accessPolicy":{"allowedOperations":[{"resourceType":"` + rt + `","operations":["` + op + `"]}]}}`))
		case strings.HasSuffix(r.URL.Path, "/resources"):
			_, _ = w.Write([]byte(`{"User:alice":{"R":[{"resourceType":"` + rt + `","name":"` + name + `","patternType":"` + pattern + `"}]}}`))
		default:
			http.NotFound(w, r)
		}
	}
}

// TestPrincipalGrantOverlaps is a direct, in-package guard for the
// DENY-removal-safety predicate (the P1 security fix). It is exercised
// cross-package by the delete/deny tests, but the wrong-oracle lesson
// (TESTING.md §2.5) says the predicate must be pinned at its own seam so
// the rule and the live re-check can't drift. Cases are derived from the
// DENY-safety domain (LITERAL×PREFIXED matrix in both directions), NOT
// from the implementation, and crucially include the cases LookupAllowed's
// coverage semantics would MISS: a LITERAL/narrower grant INSIDE a PREFIXED
// DENY, which overlaps even though the grant's pattern type differs from
// the DENY's.
func TestPrincipalGrantOverlaps(t *testing.T) {
	cases := []struct {
		name string
		// the grant MDS reports for the principal
		grantType string
		grantName string
		grantOp   string
		grantRT   string
		// the DENY's resource we're testing removal-safety for
		denyOp   types.Operation
		denyRT   types.ResourceType
		denyName string
		denyPat  types.PatternType
		want     bool
	}{
		{
			name:      "literal grant inside prefixed deny overlaps (the P1 bug)",
			grantType: "LITERAL", grantName: "secret-prod", grantOp: "Read", grantRT: "Topic",
			denyOp: types.OpRead, denyRT: types.ResourceTopic, denyName: "secret-", denyPat: types.PatternPrefixed,
			want: true,
		},
		{
			name:      "narrower prefixed grant inside prefixed deny overlaps",
			grantType: "PREFIXED", grantName: "secret-prod-", grantOp: "Read", grantRT: "Topic",
			denyOp: types.OpRead, denyRT: types.ResourceTopic, denyName: "secret-", denyPat: types.PatternPrefixed,
			want: true,
		},
		{
			name:      "wildcard literal grant overlaps any prefixed deny",
			grantType: "LITERAL", grantName: "*", grantOp: "Read", grantRT: "Topic",
			denyOp: types.OpRead, denyRT: types.ResourceTopic, denyName: "secret-", denyPat: types.PatternPrefixed,
			want: true,
		},
		{
			name:      "literal grant outside prefixed deny is disjoint",
			grantType: "LITERAL", grantName: "public-data", grantOp: "Read", grantRT: "Topic",
			denyOp: types.OpRead, denyRT: types.ResourceTopic, denyName: "secret-", denyPat: types.PatternPrefixed,
			want: false,
		},
		{
			name:      "operation mismatch is ignored (no overlap)",
			grantType: "LITERAL", grantName: "secret-prod", grantOp: "Write", grantRT: "Topic",
			denyOp: types.OpRead, denyRT: types.ResourceTopic, denyName: "secret-", denyPat: types.PatternPrefixed,
			want: false,
		},
		{
			name:      "resource-type mismatch is ignored (no overlap)",
			grantType: "LITERAL", grantName: "secret-prod", grantOp: "Read", grantRT: "Group",
			denyOp: types.OpRead, denyRT: types.ResourceTopic, denyName: "secret-", denyPat: types.PatternPrefixed,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(grantFake(tc.grantRT, tc.grantName, tc.grantType, tc.grantOp))
			defer srv.Close()

			cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
			got, err := mds.PrincipalGrantOverlaps(cl, "User:alice", tc.denyOp, tc.denyRT, tc.denyName, tc.denyPat, overlapScope)
			if err != nil {
				t.Fatalf("PrincipalGrantOverlaps: %v", err)
			}
			if got != tc.want {
				t.Errorf("overlap = %v, want %v (grant %s %q op=%s rt=%s vs deny %s %q)",
					got, tc.want, tc.grantType, tc.grantName, tc.grantOp, tc.grantRT, tc.denyPat, tc.denyName)
			}
		})
	}
}

// TestPrincipalGrantOverlaps_UnknownPatternIsConservative pins the
// fail-safe default: a grant pattern type the tool doesn't recognise must
// be treated as overlapping (unsafe to remove the DENY) rather than
// silently ignored. A regression that "continue"d on unknown types would
// wrongly report the DENY removable.
func TestPrincipalGrantOverlaps_UnknownPatternIsConservative(t *testing.T) {
	srv := httptest.NewServer(grantFake("Topic", "whatever", "FUTURE_MATCH", "Read"))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	got, err := mds.PrincipalGrantOverlaps(cl, "User:alice", types.OpRead, types.ResourceTopic, "secret-", types.PatternPrefixed, overlapScope)
	if err != nil {
		t.Fatalf("PrincipalGrantOverlaps: %v", err)
	}
	if !got {
		t.Error("an unrecognised grant pattern type must be treated as overlapping (unsafe), got non-overlap")
	}
}

// TestPrincipalGrantOverlaps_LookupErrorPropagates guards that a failed MDS
// lookup surfaces as (false, error) — never a silent (false, nil) that the
// caller would read as "safe to remove". Removing a DENY on the strength of
// a lookup we couldn't perform is exactly the dangerous behaviour the
// security fix forbids.
func TestPrincipalGrantOverlaps_LookupErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	got, err := mds.PrincipalGrantOverlaps(cl, "User:alice", types.OpRead, types.ResourceTopic, "secret-", types.PatternPrefixed, overlapScope)
	if err == nil {
		t.Fatal("expected error to propagate from a failed lookup")
	}
	if got {
		t.Error("overlap must be false (with the error) on lookup failure; never report removable on error")
	}
}
