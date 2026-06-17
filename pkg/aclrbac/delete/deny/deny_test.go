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
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

func TestGenerate_RoutesThroughDeleteDenyOne(t *testing.T) {
	dir := t.TempDir()

	plan := types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings:      []types.Binding{},
		Rejected: []types.RejectedEntry{{
			SourceACLIDs: []int{99}, Reason: "DENY_PERMISSION", Detail: "deny ...",
		}},
		Unmapped: []types.UnmappedEntry{},
		Warnings: []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{{
			SourceACLID: 99, Status: types.DenySafeToRemove,
		}},
	}
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, plan); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatal(err)
	}

	acls := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{{
			ID: 99, Principal: "User:eve", Host: "*",
			Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets",
			PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny,
		}},
	}
	aclsPath := filepath.Join(dir, "acls.json")
	if err := rundir.WriteACLs(aclsPath, acls); err != nil {
		t.Fatal(err)
	}

	if err := deny.Generate(deny.Options{
		RunDir:           dir,
		PlanPath:         planPath,
		ACLsPath:         aclsPath,
		Verify:           []verify.Result{},
		Principals:       []string{"User:eve"},
		BootstrapServers: "kafka.example.com:9093",
		MDSURL:           "https://mds.example.com",
		MDSTokenFile:     dummyTokenFile(t, dir),
	}); err != nil {
		t.Fatalf("generate: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dir, "delete-deny-acls.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	if !strings.Contains(script, "delete-deny-one --run-dir") {
		t.Errorf("script must invoke delete-deny-one:\n%s", script)
	}
	if !strings.Contains(script, "source") {
		t.Errorf("script must source runtime.env:\n%s", script)
	}
	if !strings.Contains(script, "trap") {
		t.Errorf("script must include an EXIT trap (spec §4.3 contract):\n%s", script)
	}
	// The runtime.env-cleanup trap MUST be armed before the plan.sha256
	// integrity guard, so an early guard exit (hash mismatch / unhashable /
	// bad runtime.env mode) still removes the per-run auth-token file.
	// Regression guard: the trap once sat AFTER the guard, orphaning runtime.env
	// on early exits (contradicting the documented "removed when the script
	// exits").
	trapIdx := strings.Index(script, "trap '")
	guardIdx := strings.Index(script, "EXPECTED_PLAN_SHA256")
	if trapIdx < 0 || guardIdx < 0 {
		t.Fatalf("expected both an EXIT trap and the plan.sha256 guard:\n%s", script)
	}
	if trapIdx > guardIdx {
		t.Errorf("EXIT trap (idx %d) must be armed BEFORE the plan.sha256 guard (idx %d) so early exits still clean up runtime.env:\n%s",
			trapIdx, guardIdx, script)
	}
	if !strings.Contains(script, "rm -f ") {
		t.Errorf("EXIT trap must remove runtime.env:\n%s", script)
	}
	// Spec §4.4 preflight: refuse to source runtime.env unless mode 0600
	// (it holds the per-run auth token). The script must stat the file and
	// bail on a non-600 mode.
	if !strings.Contains(script, "stat -c '%a'") || !strings.Contains(script, `!= "600"`) {
		t.Errorf("script must check runtime.env is mode 0600 before sourcing:\n%s", script)
	}

	// RUNTIME_AUTH_TOKEN must be EXPORTED so the delete-deny-one child
	// process inherits it. `source runtime.env` only sets a shell variable;
	// without an explicit `export`, the child sees an empty token and every
	// ACL fails the handshake (the whole run aborts under set -e). The export
	// must come AFTER the source (so the variable exists) and BEFORE the
	// first delete-deny-one invocation.
	exportIdx := strings.Index(script, "export RUNTIME_AUTH_TOKEN")
	sourceIdx := strings.Index(script, "source ")
	oneIdx := strings.Index(script, "delete-deny-one --run-dir")
	if exportIdx < 0 {
		t.Errorf("script must `export RUNTIME_AUTH_TOKEN` so the child inherits it:\n%s", script)
	} else if exportIdx < sourceIdx || exportIdx > oneIdx {
		t.Errorf("`export RUNTIME_AUTH_TOKEN` must appear after `source` and before delete-deny-one (source=%d export=%d one=%d):\n%s",
			sourceIdx, exportIdx, oneIdx, script)
	}

	if _, err := os.Stat(filepath.Join(dir, "runtime.env")); err != nil {
		t.Errorf("runtime.env not written: %v", err)
	}
}

// TestGenerate_RefusesWhenVerifyNotConfirmed pins that delete-deny-acls
// refuses to generate when verify.json carries a non-OK status — the RBAC
// replacement is not confirmed, so removing the source DENYs is unsafe.
func TestGenerate_RefusesWhenVerifyNotConfirmed(t *testing.T) {
	dir := t.TempDir()
	plan := types.Plan{
		SchemaVersion: "1", GeneratedAt: "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{}, Unmapped: []types.UnmappedEntry{}, Warnings: []types.Warning{},
		Rejected:     []types.RejectedEntry{{SourceACLIDs: []int{99}, Reason: "DENY_PERMISSION"}},
		DenyAnalysis: []types.DenyAnalysisEntry{{SourceACLID: 99, Status: types.DenySafeToRemove}},
	}
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, plan); err != nil {
		t.Fatal(err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatal(err)
	}
	acls := types.ACLSet{
		SchemaVersion: "1", Source: types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{{ID: 99, Principal: "User:eve", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets", PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny}},
	}
	aclsPath := filepath.Join(dir, "acls.json")
	if err := rundir.WriteACLs(aclsPath, acls); err != nil {
		t.Fatal(err)
	}
	err := deny.Generate(deny.Options{
		RunDir: dir, PlanPath: planPath, ACLsPath: aclsPath,
		Verify:           []verify.Result{{BindingID: "rb-x", Status: verify.StatusEffectiveMissing}},
		Principals:       []string{"User:eve"},
		BootstrapServers: "kafka.example.com:9093",
		MDSURL:           "https://mds.example.com",
		MDSTokenFile:     dummyTokenFile(t, dir),
	})
	if err == nil {
		t.Fatal("expected refusal when a verify result is not confirmed (EFFECTIVE_MISSING)")
	}
}

func TestOne_TokenMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	_, _ = common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "k:1",
		AuthToken:        "correct-token",
	})
	// Token mismatch is checked before plan.json so we don't need to
	// seed a plan here.

	err := deny.RunOne(deny.OneOptions{
		RunDir:   dir,
		ACLID:    1,
		EnvToken: "wrong-token",
	})
	if err == nil {
		t.Fatal("expected error for token mismatch")
	}
}

// writeMinimalPlan stages a valid plan.json + plan.json.sha256 in dir,
// plus a verify.json whose plan_sha256 matches it. Used by RunOne tests
// that need to pass the §4.4 plan-checksum check and the B4 verify-bound-
// to-plan check before exercising downstream behaviour.
// writeMinimalPlan writes a plan + checksum + matching verify.json. The
// given ACL ids are marked SAFE_TO_REMOVE in deny_analysis so delete-deny-one
// passes the §4.4 classification gate; default {1} matches the ACLID most
// tests target. Pass an explicit set (including none) to exercise the gate.
func writeMinimalPlan(t *testing.T, dir string, safeIDs ...int) {
	t.Helper()
	if safeIDs == nil {
		safeIDs = []int{1}
	}
	denyAnalysis := make([]types.DenyAnalysisEntry, 0, len(safeIDs))
	rejected := make([]types.RejectedEntry, 0, len(safeIDs))
	for _, id := range safeIDs {
		denyAnalysis = append(denyAnalysis, types.DenyAnalysisEntry{
			SourceACLID: id, Status: types.DenySafeToRemove,
		})
		// A real plan puts every DENY in rejected[] (DENY never auto-converts).
		// delete-deny-one re-checks rejected[] membership (spec §4.4), so the
		// fixture must mirror that or the gate would (correctly) refuse.
		rejected = append(rejected, types.RejectedEntry{
			SourceACLIDs: []int{id}, Reason: "DENY_PERMISSION",
		})
	}
	plan := types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings:      []types.Binding{},
		Rejected:      rejected,
		Unmapped:      []types.UnmappedEntry{},
		Warnings:      []types.Warning{},
		DenyAnalysis:  denyAnalysis,
	}
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, plan); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("write plan checksum: %v", err)
	}
	writeMatchingVerify(t, dir, planPath)
}

// writeMatchingVerify writes a verify.json into dir whose plan_sha256
// matches the plan at planPath, so delete-deny-one's B4 binding check
// passes.
func writeMatchingVerify(t *testing.T, dir, planPath string) {
	t.Helper()
	planSHA, err := common.FileSHA256(planPath)
	if err != nil {
		t.Fatalf("hash plan: %v", err)
	}
	body := []byte(`{"schema_version":"1","plan_sha256":"` + planSHA + `","results":[],"counts":{"total":0,"effective_ok":0,"effective_missing":0,"effective_unknown":0}}`)
	if err := os.WriteFile(filepath.Join(dir, "verify.json"), body, 0o600); err != nil {
		t.Fatalf("write verify.json: %v", err)
	}
}

func TestOne_SafeToRemoveProceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	// Seed an MDS bearer token file referenced by runtime.env so
	// RunOne can authenticate (spec §4.4 live re-check requires MDS).
	tokFile := filepath.Join(dir, "mds.token")
	if err := os.WriteFile(tokFile, []byte("seeded-bearer-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "k:1",
		MDSURL:           srv.URL,
		MDSTokenFile:     tokFile,
		AuthToken:        "tok",
	})

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
	writeMinimalPlan(t, dir)

	err := deny.RunOne(deny.OneOptions{
		RunDir:        dir,
		ACLID:         1,
		EnvToken:      "tok",
		ExecKafkaACLs: stubExecOK,
	})
	if err != nil {
		t.Fatalf("run one: %v", err)
	}
}

func stubExecOK(args []string) error { return nil }

// TestOne_RemovePassesDenyHost pins that the generated kafka-acls --remove for
// a host-restricted DENY carries --deny-host <host>. Without it the filter
// defaults to host "*", matches nothing for a concrete-host DENY, exits 0, and
// the audit log falsely records the DENY as removed while it is still live.
func TestOne_RemovePassesDenyHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokFile := filepath.Join(dir, "mds.token")
	if err := os.WriteFile(tokFile, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "k:1",
		MDSURL:           srv.URL,
		MDSTokenFile:     tokFile,
		AuthToken:        "tok",
	})
	aclSet := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{{
			ID: 1, Principal: "User:eve", Host: "10.0.0.5",
			Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets",
			PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny,
		}},
	}
	if err := rundir.WriteACLs(filepath.Join(dir, "acls.json"), aclSet); err != nil {
		t.Fatal(err)
	}
	writeMinimalPlan(t, dir)

	var gotArgs []string
	err := deny.RunOne(deny.OneOptions{
		RunDir:        dir,
		ACLID:         1,
		EnvToken:      "tok",
		ExecKafkaACLs: func(args []string) error { gotArgs = args; return nil },
	})
	if err != nil {
		t.Fatalf("run one: %v", err)
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, "--deny-host 10.0.0.5") {
		t.Errorf("remove argv must carry --deny-host 10.0.0.5; got %q", joined)
	}
}

// TestOne_SendsBearerTokenToMDS asserts that RunOne loads the
// MDS_TOKEN_FILE referenced from runtime.env and forwards it as a
// Bearer header on every MDS call. This is the regression guard for
// the "delete-deny-one unauthenticated -> every ACL EFFECTIVE_UNKNOWN"
// bug: without the Authorization header, MDS returns 401, LookupAllowed
// fails, and the generated DENY-deletion script skips every row.
func TestOne_SendsBearerTokenToMDS(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokFile := filepath.Join(dir, "mds.token")
	const wantToken = "super-secret-bearer"
	if err := os.WriteFile(tokFile, []byte(wantToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "k:1",
		MDSURL:           srv.URL,
		MDSTokenFile:     tokFile,
		AuthToken:        "tok",
	})

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
	writeMinimalPlan(t, dir)

	err := deny.RunOne(deny.OneOptions{
		RunDir:        dir,
		ACLID:         1,
		EnvToken:      "tok",
		ExecKafkaACLs: stubExecOK,
	})
	if err != nil {
		t.Fatalf("run one: %v", err)
	}
	wantHeader := "Bearer " + wantToken
	if gotAuth != wantHeader {
		t.Errorf("MDS did not receive bearer header; got Authorization=%q want %q", gotAuth, wantHeader)
	}
}

// TestOne_MissingMDSCredsFails asserts a clear error when runtime.env
// has no MDS_TOKEN_FILE and no MDS_USER. Previously RunOne silently
// proceeded with an unauthenticated client and every ACL hit
// EFFECTIVE_UNKNOWN.
func TestOne_MissingMDSCredsFails(t *testing.T) {
	dir := t.TempDir()
	_, _ = common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "k:1",
		MDSURL:           "https://mds.example.com",
		// no MDSTokenFile, no MDSUser
		AuthToken: "tok",
	})
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
	writeMinimalPlan(t, dir)

	err := deny.RunOne(deny.OneOptions{
		RunDir:        dir,
		ACLID:         1,
		EnvToken:      "tok",
		ExecKafkaACLs: stubExecOK,
	})
	if err == nil {
		t.Fatal("expected error for missing MDS credentials")
	}
	if !strings.Contains(err.Error(), "MDS token") && !strings.Contains(err.Error(), "credentials") {
		t.Errorf("error should explain missing MDS creds; got: %v", err)
	}
}

// writeWildcardDenyFixtures stages a plan + acls.json in dir where the
// only DENY ACL has principal `principal`. The plan DELIBERATELY marks the
// row SAFE_TO_REMOVE — even for wildcard principals the real planner would
// classify UNKNOWN — so the wildcard-refusal test exercises the delete path's
// independent defence-in-depth re-check rather than relying on the plan's
// deny_analysis. The principal is included in the operator's --principal list
// so the row survives that filter too. Returns paths to plan + acls.
func writeWildcardDenyFixtures(t *testing.T, dir, principal string) (planPath, aclsPath string) {
	t.Helper()
	plan := types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings:      []types.Binding{},
		Rejected: []types.RejectedEntry{{
			SourceACLIDs: []int{77}, Reason: "DENY_PERMISSION", Detail: "wildcard deny ...",
		}},
		Unmapped: []types.UnmappedEntry{},
		Warnings: []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{{
			SourceACLID: 77, Status: types.DenySafeToRemove,
		}},
	}
	planPath = filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, plan); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatal(err)
	}
	acls := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{{
			ID: 77, Principal: principal, Host: "*",
			Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets",
			PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny,
		}},
	}
	aclsPath = filepath.Join(dir, "acls.json")
	if err := rundir.WriteACLs(aclsPath, acls); err != nil {
		t.Fatal(err)
	}
	return planPath, aclsPath
}

// TestGenerate_WildcardDenyRefused is the lock-down regression guard (P2):
// a wildcard-principal DENY must NEVER be removable, with no confirmation-token
// escape hatch. Crucially, the fixture LIES — it marks the wildcard DENY
// SAFE_TO_REMOVE in plan.json — yet the delete path must still refuse, because
// pickEligibleDeny re-checks the wildcard shape independently of plan.json
// (defence in depth against a hand-edited or buggy plan). Both the typed
// "User:*" form and the bare "*" form (the original P2 bug) are covered.
func TestGenerate_WildcardDenyRefused(t *testing.T) {
	for _, principal := range []string{"User:*", "*"} {
		t.Run(principal, func(t *testing.T) {
			dir := t.TempDir()
			planPath, aclsPath := writeWildcardDenyFixtures(t, dir, principal)

			err := deny.Generate(deny.Options{
				RunDir:           dir,
				PlanPath:         planPath,
				ACLsPath:         aclsPath,
				Verify:           []verify.Result{},
				Principals:       []string{principal},
				BootstrapServers: "kafka.example.com:9093",
				MDSURL:           "https://mds.example.com",
				MDSTokenFile:     dummyTokenFile(t, dir),
			})
			if err == nil {
				t.Fatalf("expected wildcard DENY %q to be refused, got nil error", principal)
			}
			if !strings.Contains(err.Error(), "UNKNOWN") || !strings.Contains(err.Error(), "cannot be removed") {
				t.Errorf("error should explain the wildcard DENY is UNKNOWN and cannot be removed; got: %v", err)
			}
			if !strings.Contains(err.Error(), principal) {
				t.Errorf("error should name the offending wildcard principal %q; got: %v", principal, err)
			}
			// No script must be written when the only candidate is refused.
			if _, statErr := os.Stat(filepath.Join(dir, "delete-deny-acls.sh")); statErr == nil {
				t.Errorf("delete-deny-acls.sh must NOT be written for a wildcard DENY")
			}
		})
	}
}

// TestGenerate_NonWildcardSucceeds proves the common case still works: a
// concrete-principal DENY marked SAFE_TO_REMOVE generates the script.
func TestGenerate_NonWildcardSucceeds(t *testing.T) {
	dir := t.TempDir()
	planPath, aclsPath := writeWildcardDenyFixtures(t, dir, "User:eve")

	if err := deny.Generate(deny.Options{
		RunDir:           dir,
		PlanPath:         planPath,
		ACLsPath:         aclsPath,
		Verify:           []verify.Result{},
		Principals:       []string{"User:eve"},
		BootstrapServers: "kafka.example.com:9093",
		MDSURL:           "https://mds.example.com",
		MDSTokenFile:     dummyTokenFile(t, dir),
	}); err != nil {
		t.Fatalf("generate for a concrete-principal SAFE_TO_REMOVE DENY: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "delete-deny-acls.sh")); err != nil {
		t.Errorf("script should be written: %v", err)
	}
}

// dummyTokenFile writes a one-line token to a temp file inside dir so
// deny.Generate's MDS-auth pre-check is satisfied without standing up a
// fake MDS server. The token never gets used: these tests don't execute
// the generated script.
func dummyTokenFile(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "mds-token")
	if err := os.WriteFile(p, []byte("dummy-test-token\n"), 0o600); err != nil {
		t.Fatalf("write dummy token file: %v", err)
	}
	return p
}

// TestGenerate_RejectsMissingMDSURL asserts the spec §4.4 invariant that
// delete-deny-acls cannot generate a script without an MDS URL: the live
// re-check delete-deny-one performs has nowhere to go.
func TestGenerate_RejectsMissingMDSURL(t *testing.T) {
	dir := t.TempDir()
	planPath, aclsPath := writeWildcardDenyFixtures(t, dir, "User:eve")

	err := deny.Generate(deny.Options{
		RunDir:           dir,
		PlanPath:         planPath,
		ACLsPath:         aclsPath,
		Verify:           []verify.Result{},
		Principals:       []string{"User:eve"},
		BootstrapServers: "kafka.example.com:9093",
		// MDSURL intentionally empty
		MDSTokenFile: dummyTokenFile(t, dir),
	})
	if err == nil {
		t.Fatal("expected error for missing --mds-url")
	}
	if !strings.Contains(err.Error(), "--mds-url") {
		t.Errorf("error should name the missing flag --mds-url; got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "delete-deny-acls.sh")); statErr == nil {
		t.Error("script should not be written when validation fails")
	}
}

// TestGenerate_RejectsMissingMDSAuth asserts that delete-deny-acls
// refuses to write a script with no MDS credentials in runtime.env.
// Previously the failure was deferred until delete-deny-one token
// resolution at script execution time.
func TestGenerate_RejectsMissingMDSAuth(t *testing.T) {
	dir := t.TempDir()
	planPath, aclsPath := writeWildcardDenyFixtures(t, dir, "User:eve")

	err := deny.Generate(deny.Options{
		RunDir:           dir,
		PlanPath:         planPath,
		ACLsPath:         aclsPath,
		Verify:           []verify.Result{},
		Principals:       []string{"User:eve"},
		BootstrapServers: "kafka.example.com:9093",
		MDSURL:           "https://mds.example.com",
		// No MDSTokenFile, no MDSUser+MDSPasswordFile
	})
	if err == nil {
		t.Fatal("expected error for missing MDS authentication")
	}
	if !strings.Contains(err.Error(), "--mds-token-file") || !strings.Contains(err.Error(), "--mds-user") {
		t.Errorf("error should name both auth paths; got: %v", err)
	}
}

// TestGenerate_RejectsMissingBootstrapServer asserts that delete-deny-acls
// refuses to write a script with no bootstrap server: the generated
// `kafka-acls --remove` invocation needs one. Previously surfaced only
// at `bash delete-deny-acls.sh` time as `--bootstrap-server ""`.
func TestGenerate_RejectsMissingBootstrapServer(t *testing.T) {
	dir := t.TempDir()
	planPath, aclsPath := writeWildcardDenyFixtures(t, dir, "User:eve")

	err := deny.Generate(deny.Options{
		RunDir:       dir,
		PlanPath:     planPath,
		ACLsPath:     aclsPath,
		Verify:       []verify.Result{},
		Principals:   []string{"User:eve"},
		MDSURL:       "https://mds.example.com",
		MDSTokenFile: dummyTokenFile(t, dir),
		// BootstrapServers intentionally empty
	})
	if err == nil {
		t.Fatal("expected error for missing --bootstrap-server")
	}
	if !strings.Contains(err.Error(), "--bootstrap-server") {
		t.Errorf("error should name --bootstrap-server; got: %v", err)
	}
}

// TestGenerate_RejectsWhitespaceOnlyMDSURL is the B9 regression guard:
// a whitespace-only --mds-url (e.g. an empty shell variable that expanded
// to spaces) must be rejected at generation time, not slip past the
// empty-string check and defer the failure to script execution.
func TestGenerate_RejectsWhitespaceOnlyMDSURL(t *testing.T) {
	dir := t.TempDir()
	planPath, aclsPath := writeWildcardDenyFixtures(t, dir, "User:eve")

	err := deny.Generate(deny.Options{
		RunDir:           dir,
		PlanPath:         planPath,
		ACLsPath:         aclsPath,
		Verify:           []verify.Result{},
		Principals:       []string{"User:eve"},
		BootstrapServers: "kafka.example.com:9093",
		MDSURL:           "   ",
		MDSTokenFile:     dummyTokenFile(t, dir),
	})
	if err == nil {
		t.Fatal("expected error for whitespace-only --mds-url")
	}
	if !strings.Contains(err.Error(), "--mds-url") {
		t.Errorf("error should name --mds-url; got: %v", err)
	}
}

// TestGenerate_AcceptsUserPasswordAuth confirms the MDS-auth check
// accepts the --mds-user + --mds-password-file path as an alternative
// to --mds-token-file. Defends against an over-strict validator that
// would force one specific auth shape.
func TestGenerate_AcceptsUserPasswordAuth(t *testing.T) {
	dir := t.TempDir()
	planPath, aclsPath := writeWildcardDenyFixtures(t, dir, "User:eve")

	pwFile := filepath.Join(dir, "mds-password")
	if err := os.WriteFile(pwFile, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatalf("write dummy password file: %v", err)
	}

	if err := deny.Generate(deny.Options{
		RunDir:           dir,
		PlanPath:         planPath,
		ACLsPath:         aclsPath,
		Verify:           []verify.Result{},
		Principals:       []string{"User:eve"},
		BootstrapServers: "kafka.example.com:9093",
		MDSURL:           "https://mds.example.com",
		MDSUser:          "alice",
		MDSPasswordFile:  pwFile,
	}); err != nil {
		t.Fatalf("generate with user+password auth: %v", err)
	}
}
