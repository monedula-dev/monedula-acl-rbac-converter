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

// TestOne_PlanTamperingDetected guards spec §4.4: delete-deny-one must
// re-verify plan.json's checksum before making any MDS call. Tampering
// with plan.json between `delete-deny-acls` script generation and per-ACL
// execution must be detected.
func TestOne_PlanTamperingDetected(t *testing.T) {
	dir := t.TempDir()
	_, _ = common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "k:1",
		MDSURL:           "https://mds.example.com",
		AuthToken:        "tok",
	})
	// Seed acls.json so any other check that runs first wouldn't trip
	// over a missing input.
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

	// Write a valid plan + checksum, then mutate the plan so the recorded
	// digest no longer matches.
	plan := types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings:      []types.Binding{},
		Rejected:      []types.RejectedEntry{},
		Unmapped:      []types.UnmappedEntry{},
		Warnings:      []types.Warning{},
		DenyAnalysis:  []types.DenyAnalysisEntry{},
	}
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, plan); err != nil {
		t.Fatal(err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatal(err)
	}
	// Tamper: append a byte to plan.json without rewriting the checksum.
	f, err := os.OpenFile(planPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(" ")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	err = deny.RunOne(deny.OneOptions{
		RunDir:        dir,
		ACLID:         1,
		EnvToken:      "tok",
		ExecKafkaACLs: func(args []string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected error for tampered plan.json")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("error should mention checksum; got: %v", err)
	}
}

// TestOne_VerifyPlanMismatchRefused is the B4 regression guard for
// delete-deny-one: when verify.json's stamped plan_sha256 does not match
// the run-dir plan.json, the SAFE_TO_REMOVE evidence came from a
// different plan and must be refused before any MDS/kafka-acls call.
func TestOne_VerifyPlanMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	_, _ = common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "k:1",
		MDSURL:           "https://mds.example.com",
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
	// Valid plan + checksum, but a verify.json stamped with a hash that
	// does not match the plan.
	plan := types.Plan{
		SchemaVersion: "1", GeneratedAt: "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{}, Rejected: []types.RejectedEntry{},
		Unmapped: []types.UnmappedEntry{}, Warnings: []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{},
	}
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, plan); err != nil {
		t.Fatal(err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatal(err)
	}
	wrong := `{"schema_version":"1","plan_sha256":"2222222222222222222222222222222222222222222222222222222222222222","results":[],"counts":{"total":0,"effective_ok":0,"effective_missing":0,"effective_unknown":0}}`
	if err := os.WriteFile(filepath.Join(dir, "verify.json"), []byte(wrong), 0o600); err != nil {
		t.Fatal(err)
	}

	err := deny.RunOne(deny.OneOptions{
		RunDir:        dir,
		ACLID:         1,
		EnvToken:      "tok",
		ExecKafkaACLs: func(args []string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected error for verify.json bound to a different plan")
	}
	if !strings.Contains(err.Error(), "different plan") {
		t.Errorf("error should explain plan mismatch; got: %v", err)
	}
}

// TestOne_PrefixedDenyEmitsPatternType is a regression guard for B1:
// kafka-acls treats `--resource-pattern-type` as LITERAL when the flag is
// omitted, so a PREFIXED DENY would silently fail to match (no-op) under
// the old delete-deny-one argv builder. Every kafka-acls invocation
// emitted by delete-deny-one must include `--resource-pattern-type
// <lower(PatternType)>`.
func TestOne_PrefixedDenyEmitsPatternType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// MDS reports no resources -> not allowed -> SAFE_TO_REMOVE
		// path; kafka-acls --remove gets invoked.
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokFile := filepath.Join(dir, "mds.token")
	if err := os.WriteFile(tokFile, []byte("seeded"), 0o600); err != nil {
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
			Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secret-",
			PatternType: types.PatternPrefixed, PermissionType: types.PermissionDeny,
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
	if !strings.Contains(joined, "--resource-pattern-type prefixed") {
		t.Errorf("kafka-acls argv must contain --resource-pattern-type prefixed; got:\n%s", joined)
	}
}

// TestOne_DelegationTokenDeny is the B12 regression guard: a DENY on a
// DelegationToken resource must emit --delegation-token in the kafka-acls
// argv. The switch previously had no case for it, so the resource flag
// was silently dropped and kafka-acls --remove targeted the wrong scope.
func TestOne_DelegationTokenDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokFile := filepath.Join(dir, "mds.token")
	if err := os.WriteFile(tokFile, []byte("seeded"), 0o600); err != nil {
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
			Operation: types.OpDescribe, ResourceType: types.ResourceDelegationToken, ResourceName: "tok-hash",
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
	if !strings.Contains(joined, "--delegation-token tok-hash") {
		t.Errorf("kafka-acls argv must contain --delegation-token tok-hash; got:\n%s", joined)
	}
}

// TestOne_InsecureSkipVerifyHonoured is the P2a regression guard: the TLS
// posture the operator chose at delete-deny-acls generation time must be
// carried through runtime.env into the per-ACL client that delete-deny-one
// rebuilds. We stand up an httptest TLS server with a self-signed cert
// (the default for NewTLSServer). With MDS_INSECURE_SKIP_VERIFY absent the
// live re-check fails TLS verification; with it set to true the same call
// succeeds and the ACL is removed — proving env.InsecureSkipVerify reaches
// mds.NewClient.
func TestOne_InsecureSkipVerifyHonoured(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No matching resources -> not allowed -> SAFE_TO_REMOVE path.
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	run := func(t *testing.T, insecure bool) (gotArgs []string, log string, err error) {
		dir := t.TempDir()
		tokFile := filepath.Join(dir, "mds.token")
		if werr := os.WriteFile(tokFile, []byte("seeded"), 0o600); werr != nil {
			t.Fatal(werr)
		}
		if _, werr := common.WriteRuntimeEnv(dir, common.RuntimeEnv{
			BootstrapServers:   "k:1",
			MDSURL:             srv.URL, // https:// with a self-signed cert
			MDSTokenFile:       tokFile,
			InsecureSkipVerify: insecure,
			AuthToken:          "tok",
		}); werr != nil {
			t.Fatal(werr)
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
		if werr := rundir.WriteACLs(filepath.Join(dir, "acls.json"), aclSet); werr != nil {
			t.Fatal(werr)
		}
		writeMinimalPlan(t, dir)

		err = deny.RunOne(deny.OneOptions{
			RunDir:        dir,
			ACLID:         1,
			EnvToken:      "tok",
			ExecKafkaACLs: func(args []string) error { gotArgs = args; return nil },
		})
		logBody, _ := os.ReadFile(filepath.Join(dir, "delete-deny.log"))
		return gotArgs, string(logBody), err
	}

	t.Run("skip-verify true reaches MDS and removes", func(t *testing.T) {
		gotArgs, _, err := run(t, true)
		if err != nil {
			t.Fatalf("with insecure-skip-verify the live re-check should succeed; got: %v", err)
		}
		if len(gotArgs) == 0 {
			t.Errorf("expected kafka-acls --remove to be invoked; got no argv")
		}
	})

	t.Run("skip-verify false cannot reach MDS so the ACL is not removed", func(t *testing.T) {
		// When the TLS posture is NOT carried through, the live re-check
		// can't complete the handshake against the self-signed cert. That
		// is a non-auth MDS error, so RunOne records EFFECTIVE_UNKNOWN and
		// declines to remove the ACL (no kafka-acls argv). This is the
		// fail-safe outcome the round-trip must preserve.
		gotArgs, log, err := run(t, false)
		if err != nil {
			t.Fatalf("non-auth re-check failure should be logged as SKIP, not returned: %v", err)
		}
		if len(gotArgs) != 0 {
			t.Errorf("ACL must NOT be removed when MDS is unreachable; got argv: %v", gotArgs)
		}
		if !strings.Contains(log, "EFFECTIVE_UNKNOWN") {
			t.Errorf("expected an EFFECTIVE_UNKNOWN SKIP in delete-deny.log; got:\n%s", log)
		}
	})
}

// TestOne_MDSAuthErrorAborts asserts that delete-deny-one returns a
// non-nil error (not a silent SKIP log line) when MDS returns 401/403.
// Previously the auth error was caught as "live re-check failed" and
// turned into a SKIP for every ACL — defeating the whole point of the
// live re-check and silently no-op'ing the entire DENY-deletion run.
// The caller's `set -e` relies on the non-zero exit to halt the loop.
func TestOne_MDSAuthErrorAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokFile := filepath.Join(dir, "mds.token")
	if err := os.WriteFile(tokFile, []byte("expired-token"), 0o600); err != nil {
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
		ExecKafkaACLs: func(args []string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected error for MDS auth failure; got nil")
	}
	if !strings.Contains(err.Error(), "MDS authentication failed") {
		t.Errorf("error should explain MDS auth failure; got: %v", err)
	}
	// And there must be no SKIP line in delete-deny.log — the whole point
	// of this fix is that auth errors don't masquerade as SKIPs.
	logBody, _ := os.ReadFile(filepath.Join(dir, "delete-deny.log"))
	if strings.Contains(string(logBody), "SKIP") {
		t.Errorf("delete-deny.log should not contain SKIP for an auth error; got:\n%s", logBody)
	}
}
