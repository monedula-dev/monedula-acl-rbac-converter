// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package deny_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/deny"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestOne_PrefixedDenyNotRemovedWhenLiteralGrantInside is the access-grant
// blocker regression guard for the LIVE re-check. A PREFIXED DENY denies a
// whole namespace; if the principal holds a LITERAL grant for a resource
// INSIDE that namespace, removing the DENY grants access. The old re-check
// required the MDS grant's pattern type to equal the DENY's, so it ignored
// the LITERAL grant, reported "not allowed", and removed the DENY — silently
// granting access. delete-deny-one must detect the overlap and SKIP.
func TestOne_PrefixedDenyNotRemovedWhenLiteralGrantInside(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// alice holds a LITERAL Read grant on secret-prod — inside the
		// PREFIXED DENY namespace secret-*. The grant op comes from the role
		// definition; the resources lookup carries the pattern.
		switch {
		case strings.HasPrefix(r.URL.Path, "/security/1.0/roles/"):
			_, _ = w.Write([]byte(`{"name":"R","accessPolicy":{"allowedOperations":[{"resourceType":"Topic","operations":["Read"]}]}}`))
		default: // POST /lookup/principal/{p}/resources
			_, _ = w.Write([]byte(`{"User:alice":{"R":[{"resourceType":"Topic","name":"secret-prod","patternType":"LITERAL"}]}}`))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokFile := filepath.Join(dir, "mds.token")
	if err := os.WriteFile(tokFile, []byte("seeded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "k:1", MDSURL: srv.URL, MDSTokenFile: tokFile, AuthToken: "tok",
	}); err != nil {
		t.Fatal(err)
	}
	aclSet := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{{
			ID: 1, Principal: "User:alice", Host: "*",
			Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secret-",
			PatternType: types.PatternPrefixed, PermissionType: types.PermissionDeny,
		}},
	}
	if err := rundir.WriteACLs(filepath.Join(dir, "acls.json"), aclSet); err != nil {
		t.Fatal(err)
	}
	// Statically SAFE_TO_REMOVE (passes the §4.4 gate); the LIVE re-check must
	// still override and refuse removal because a grant now overlaps.
	writeMinimalPlan(t, dir)

	var execed bool
	if err := deny.RunOne(deny.OneOptions{
		RunDir: dir, ACLID: 1, EnvToken: "tok",
		ExecKafkaACLs: func(args []string) error { execed = true; return nil },
	}); err != nil {
		t.Fatalf("run one: %v", err)
	}
	if execed {
		t.Error("DENY must NOT be removed: a LITERAL grant inside the PREFIXED deny namespace means removal would grant access")
	}
	logBody, _ := os.ReadFile(filepath.Join(dir, "delete-deny.log"))
	if !strings.Contains(string(logBody), "WOULD_GRANT_ACCESS") {
		t.Errorf("expected a WOULD_GRANT_ACCESS SKIP in delete-deny.log; got:\n%s", logBody)
	}
}

// TestOne_RefusesWhenDenyAnalysisNotSafe is the spec §4.4 gate regression
// guard: a direct delete-deny-one call must refuse an ACL the planner did NOT
// classify SAFE_TO_REMOVE, even with a valid runtime token. Without this gate,
// an operator holding the per-run token could target a WOULD_GRANT_ACCESS DENY
// the generated script would never emit.
func TestOne_RefusesWhenDenyAnalysisNotSafe(t *testing.T) {
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "mds.token")
	if err := os.WriteFile(tokFile, []byte("seeded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "k:1", MDSURL: "https://mds.example.com", MDSTokenFile: tokFile, AuthToken: "tok",
	}); err != nil {
		t.Fatal(err)
	}
	aclSet := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{{
			ID: 1, Principal: "User:eve", Host: "*",
			Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets",
			PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny,
		}},
	}
	if err := rundir.WriteACLs(filepath.Join(dir, "acls.json"), aclSet); err != nil {
		t.Fatal(err)
	}
	// Plan classifies acl_id=1 WOULD_GRANT_ACCESS — the generator would never
	// emit it, but a direct call could try. acl_id=1 IS in rejected[] (a real
	// DENY), so this test exercises the deny_analysis gate specifically, not
	// the rejected[]-membership gate.
	plan := types.Plan{
		SchemaVersion: "1", GeneratedAt: "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{},
		Rejected: []types.RejectedEntry{{SourceACLIDs: []int{1}, Reason: "DENY_PERMISSION"}},
		Unmapped: []types.UnmappedEntry{}, Warnings: []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{{SourceACLID: 1, Status: types.DenyWouldGrantAccess}},
	}
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, plan); err != nil {
		t.Fatal(err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatal(err)
	}
	writeMatchingVerify(t, dir, planPath)

	var execed bool
	err := deny.RunOne(deny.OneOptions{
		RunDir: dir, ACLID: 1, EnvToken: "tok",
		ExecKafkaACLs: func(args []string) error { execed = true; return nil },
	})
	if err == nil {
		t.Fatal("expected refusal: deny_analysis for acl_id=1 is not SAFE_TO_REMOVE")
	}
	if !strings.Contains(err.Error(), "SAFE_TO_REMOVE") {
		t.Errorf("error should name the SAFE_TO_REMOVE gate; got: %v", err)
	}
	if execed {
		t.Error("must not exec kafka-acls when the §4.4 gate refuses")
	}
}

// TestOne_RefusesWhenNotInRejected is the spec §4.4 rejected[]-membership
// regression guard. The spec requires the targeted acl-id to match an entry in
// plan.json::rejected[] whose deny_analysis is SAFE_TO_REMOVE. This plan LIES:
// it fabricates a SAFE_TO_REMOVE deny_analysis entry for acl_id=1 but leaves
// rejected[] empty — the shape a hand-edit could produce to dodge the planner.
// RunOne must refuse on the rejected[] gate, before any kafka-acls exec.
func TestOne_RefusesWhenNotInRejected(t *testing.T) {
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "mds.token")
	if err := os.WriteFile(tokFile, []byte("seeded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "k:1", MDSURL: "https://mds.example.com", MDSTokenFile: tokFile, AuthToken: "tok",
	}); err != nil {
		t.Fatal(err)
	}
	aclSet := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{{
			ID: 1, Principal: "User:eve", Host: "*",
			Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets",
			PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny,
		}},
	}
	if err := rundir.WriteACLs(filepath.Join(dir, "acls.json"), aclSet); err != nil {
		t.Fatal(err)
	}
	// SAFE_TO_REMOVE deny_analysis but EMPTY rejected[] — internally
	// inconsistent, as only a hand-edit would produce.
	plan := types.Plan{
		SchemaVersion: "1", GeneratedAt: "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{}, Rejected: []types.RejectedEntry{},
		Unmapped: []types.UnmappedEntry{}, Warnings: []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{{SourceACLID: 1, Status: types.DenySafeToRemove}},
	}
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, plan); err != nil {
		t.Fatal(err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatal(err)
	}
	writeMatchingVerify(t, dir, planPath)

	var execed bool
	err := deny.RunOne(deny.OneOptions{
		RunDir: dir, ACLID: 1, EnvToken: "tok",
		ExecKafkaACLs: func(args []string) error { execed = true; return nil },
	})
	if err == nil {
		t.Fatal("expected refusal: acl_id=1 has SAFE_TO_REMOVE deny_analysis but is not in rejected[]")
	}
	if !strings.Contains(err.Error(), "rejected[]") {
		t.Errorf("error should name the rejected[] gate; got: %v", err)
	}
	if execed {
		t.Error("must not exec kafka-acls when the rejected[] gate refuses")
	}
}

// TestOne_RefusesWildcardPrincipalEvenWhenPlanSaysSafe is the P1 regression
// guard for the hidden-but-invocable helper. The generator (delete-deny-acls)
// already refuses wildcard-principal DENYs, but delete-deny-one is a real
// subcommand: a hand-edited plan.json that marks a wildcard DENY
// SAFE_TO_REMOVE (with a freshly re-validated checksum) must NOT be able to
// drive a removal through it. The refusal must happen before any kafka-acls
// exec — and before the live MDS re-check, which for a wildcard principal
// would find no grants and wrongly conclude "safe". Covers both the typed
// "User:*" and the bare "*" forms.
func TestOne_RefusesWildcardPrincipalEvenWhenPlanSaysSafe(t *testing.T) {
	for _, principal := range []string{"User:*", "*"} {
		t.Run(principal, func(t *testing.T) {
			dir := t.TempDir()
			tokFile := filepath.Join(dir, "mds.token")
			if err := os.WriteFile(tokFile, []byte("seeded"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := common.WriteRuntimeEnv(dir, common.RuntimeEnv{
				BootstrapServers: "k:1", MDSURL: "https://mds.example.com", MDSTokenFile: tokFile, AuthToken: "tok",
			}); err != nil {
				t.Fatal(err)
			}
			aclSet := types.ACLSet{
				SchemaVersion: "1",
				Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
				ACLs: []types.ACLRow{{
					ID: 1, Principal: principal, Host: "*",
					Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets",
					PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny,
				}},
			}
			if err := rundir.WriteACLs(filepath.Join(dir, "acls.json"), aclSet); err != nil {
				t.Fatal(err)
			}
			// The plan LIES: it marks the wildcard DENY SAFE_TO_REMOVE (what a
			// hand-edit + `plan --revalidate` would produce). The wildcard gate
			// must refuse anyway.
			plan := types.Plan{
				SchemaVersion: "1", GeneratedAt: "2026-05-21T10:05:00Z",
				Bindings: []types.Binding{}, Rejected: []types.RejectedEntry{},
				Unmapped: []types.UnmappedEntry{}, Warnings: []types.Warning{},
				DenyAnalysis: []types.DenyAnalysisEntry{{SourceACLID: 1, Status: types.DenySafeToRemove}},
			}
			planPath := filepath.Join(dir, "plan.json")
			if err := rundir.WritePlan(planPath, plan); err != nil {
				t.Fatal(err)
			}
			if err := rundir.WriteChecksum(planPath); err != nil {
				t.Fatal(err)
			}
			writeMatchingVerify(t, dir, planPath)

			var execed bool
			err := deny.RunOne(deny.OneOptions{
				RunDir: dir, ACLID: 1, EnvToken: "tok",
				ExecKafkaACLs: func(args []string) error { execed = true; return nil },
			})
			if err == nil {
				t.Fatalf("expected refusal for wildcard principal %q even though plan says SAFE_TO_REMOVE", principal)
			}
			if !strings.Contains(err.Error(), "wildcard") || !strings.Contains(err.Error(), "never removable") {
				t.Errorf("error should explain the wildcard DENY is never removable; got: %v", err)
			}
			if execed {
				t.Errorf("must NOT exec kafka-acls for a wildcard-principal DENY (%q)", principal)
			}
		})
	}
}
