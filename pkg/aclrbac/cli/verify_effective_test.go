// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

// TestVerifyCmd_EffectiveModeProducesEffectiveOK is a CLI-level integration
// test that proves newVerifyCmd correctly populates SourceOps and
// SourceResources from acls.json so that --mode effective returns
// EFFECTIVE_OK instead of EFFECTIVE_UNKNOWN.
//
// Setup:
//   - acls.json with one Read ACL (id=1) and one Describe ACL (id=2) for
//     User:alice on Topic "orders" LITERAL.
//   - plan.json produced by the real `plan` command (so it has a valid
//     checksum) against the same acls.json.
//   - A fake MDS that:
//     1. Returns 200 on the capability probe (GET /security/1.0/lookup/principals),
//     causing ProbeCapability to return CapabilityLookup.
//     2. Returns a lookup response that includes the (Read, Topic:orders LITERAL)
//     and (Describe, Topic:orders LITERAL) tuples so both source ACLs pass.
//
// Without the fix in newVerifyCmd the test fails with EFFECTIVE_UNKNOWN
// because SourceOps/SourceResources are nil.
func TestVerifyCmd_EffectiveModeProducesEffectiveOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/security/1.0/roles":
			// Capability probe: return 200 so ProbeCapability returns CapabilityLookup.
			w.Write([]byte(`[]`))
		case strings.HasPrefix(r.URL.Path, "/security/1.0/roles/"):
			// Role definition: DeveloperRead grants Read+Describe on Topic.
			w.Write([]byte(`{"name":"DeveloperRead","accessPolicy":{"allowedOperations":[{"resourceType":"Topic","operations":["Read","Describe"]}]}}`))
		case strings.HasPrefix(r.URL.Path, "/security/1.0/lookup/principal/"):
			// Resources lookup: the principal holds DeveloperRead on Topic:orders.
			w.Write([]byte(`{"User:alice":{"DeveloperRead":[{"resourceType":"Topic","name":"orders","patternType":"LITERAL"}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tmp := t.TempDir()
	aclsPath := filepath.Join(tmp, "acls.json")
	scopesPath := filepath.Join(tmp, "scopes.yaml")
	planPath := filepath.Join(tmp, "plan.json")
	tokenPath := filepath.Join(tmp, "token")

	const aclsJSON = `{
  "schema_version": "1",
  "source": {"type": "json", "generated_at": "2026-05-24T00:00:00Z"},
  "acls": [
    {"id": 1, "principal": "User:alice", "host": "*", "operation": "Read",     "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"},
    {"id": 2, "principal": "User:alice", "host": "*", "operation": "Describe", "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"}
  ]
}`
	if err := os.WriteFile(aclsPath, []byte(aclsJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("fake-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Build plan.json (real CLI so it gets a valid checksum).
	if exit := cli.Execute([]string{
		"plan",
		"--acls", aclsPath,
		"--scopes", scopesPath,
		"--out", planPath,
	}); exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}

	// Run verify --mode effective. Before the fix this returns non-zero
	// because every binding gets EFFECTIVE_UNKNOWN.
	exit := cli.Execute([]string{
		"verify",
		"--plan", planPath,
		"--mode", "effective",
		"--mds-url", srv.URL,
		"--mds-token-file", tokenPath,
	})

	// Read verify.json regardless of exit code so we can show what we got.
	verifyPath := filepath.Join(tmp, "verify.json")
	verifyData, readErr := os.ReadFile(verifyPath)
	if readErr != nil {
		t.Logf("could not read verify.json: %v", readErr)
	} else {
		t.Logf("verify.json: %s", verifyData)
	}

	if exit != 0 {
		t.Fatalf("verify --mode effective exit %d", exit)
	}

	if readErr != nil {
		t.Fatal("verify.json was not written")
	}

	// verify.json on disk uses the {results, counts} envelope.
	var sum verify.Summary
	if err := json.Unmarshal(verifyData, &sum); err != nil {
		t.Fatalf("parse verify.json envelope: %v", err)
	}
	results := sum.Results
	if len(results) == 0 {
		t.Fatal("verify.json has no results")
	}
	// Counts in the envelope must agree with the result list.
	if sum.Counts.Total != len(results) {
		t.Errorf("envelope counts.total=%d but results has %d entries",
			sum.Counts.Total, len(results))
	}
	for _, r := range results {
		if r.Status != verify.StatusEffectiveOK {
			t.Errorf("expected EFFECTIVE_OK for source_acl_id=%d; got %s (%s)",
				r.SourceACLID, r.Status, r.Detail)
		}
		// Regression: effective-mode Results must carry BindingID. Without it,
		// delete-acls' EligibleACLs (which indexes statuses by BindingID)
		// silently produces zero eligible ACLs after the recommended verify
		// flow. The bug was caught by tests/integration/delete_acls_roundtrip
		// against real cp-kafka; this assertion locks the fix at the unit
		// level so future refactors can't reintroduce it.
		if r.BindingID == "" {
			t.Errorf("Result for source_acl_id=%d has empty BindingID; "+
				"delete-acls eligibility lookup will silently miss it", r.SourceACLID)
		}
	}
}

// TestVerifyCmd_EffectiveMode_PrincipalUnresolved_ReturnsEffectiveMissing
// exercises the EFFECTIVE_MISSING path: the fake MDS returns an empty
// resources array so LookupAllowed returns (false, nil), and every source ACL
// ends up with StatusEffectiveMissing rather than StatusEffectiveOK or
// StatusEffectiveUnknown.
func TestVerifyCmd_EffectiveMode_PrincipalUnresolved_ReturnsEffectiveMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/security/1.0/roles":
			// Capability probe: return 200 so ProbeCapability returns CapabilityLookup.
			w.Write([]byte(`[]`))
		case strings.HasPrefix(r.URL.Path, "/security/1.0/lookup/principal/"):
			// Empty rolebindings — the principal has no grants, so every source
			// ACL maps to EFFECTIVE_MISSING.
			w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tmp := t.TempDir()
	aclsPath := filepath.Join(tmp, "acls.json")
	scopesPath := filepath.Join(tmp, "scopes.yaml")
	planPath := filepath.Join(tmp, "plan.json")
	tokenPath := filepath.Join(tmp, "token")

	// Two ACLs: Read + Describe → maps to DeveloperRead.
	const aclsJSON = `{
  "schema_version": "1",
  "source": {"type": "json", "generated_at": "2026-05-24T00:00:00Z"},
  "acls": [
    {"id": 1, "principal": "User:alice", "host": "*", "operation": "Read",     "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"},
    {"id": 2, "principal": "User:alice", "host": "*", "operation": "Describe", "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"}
  ]
}`
	if err := os.WriteFile(aclsPath, []byte(aclsJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("fake-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Build plan.json (real CLI so it gets a valid checksum).
	if exit := cli.Execute([]string{
		"plan",
		"--acls", aclsPath,
		"--scopes", scopesPath,
		"--out", planPath,
	}); exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}

	// verify --mode effective writes verify.json and exits 0 even when
	// bindings are EFFECTIVE_MISSING (the exit code only reflects errors such
	// as network failures or checksum mismatches, not result statuses).
	exit := cli.Execute([]string{
		"verify",
		"--plan", planPath,
		"--mode", "effective",
		"--mds-url", srv.URL,
		"--mds-token-file", tokenPath,
	})

	verifyPath := filepath.Join(tmp, "verify.json")
	verifyData, readErr := os.ReadFile(verifyPath)
	if readErr != nil {
		t.Logf("could not read verify.json: %v", readErr)
	} else {
		t.Logf("verify.json: %s", verifyData)
	}

	// EFFECTIVE_MISSING now exits 5 (Guardrail) — verify is the documented
	// pre-condition for `delete-acls`, and a CI gate using `verify` should
	// fail loudly rather than silently emit verify.json with bad rows. The
	// file is still written before the exit-code check, so operators can
	// inspect details on a non-zero exit.
	if exit != int(types.ExitGuardrail) {
		t.Fatalf("verify exit %d (expected %d = Guardrail; EFFECTIVE_MISSING is an unhealthy result)", exit, types.ExitGuardrail)
	}

	if readErr != nil {
		t.Fatal("verify.json was not written")
	}

	// envelope shape: {results, counts}.
	var sum verify.Summary
	if err := json.Unmarshal(verifyData, &sum); err != nil {
		t.Fatalf("parse verify.json envelope: %v", err)
	}
	results := sum.Results
	if len(results) == 0 {
		t.Fatal("verify.json has no results")
	}
	hasMissing := false
	for _, r := range results {
		if r.Status == verify.StatusEffectiveMissing {
			hasMissing = true
		}
		if r.Status == verify.StatusEffectiveUnknown {
			t.Errorf("got EFFECTIVE_UNKNOWN for source_acl_id=%d; expected EFFECTIVE_MISSING (empty resources != error)", r.SourceACLID)
		}
	}
	if !hasMissing {
		t.Errorf("expected at least one EFFECTIVE_MISSING result; statuses: %v", results)
	}
}

// TestVerifyCmd_EffectiveMode_MissingAclsJson asserts that verify --mode
// effective returns a non-zero exit when acls.json does not exist in the
// run directory, rather than silently producing EFFECTIVE_UNKNOWN.
func TestVerifyCmd_EffectiveMode_MissingAclsJson(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	tmp := t.TempDir()
	scopesPath := filepath.Join(tmp, "scopes.yaml")
	planPath := filepath.Join(tmp, "plan.json")
	tokenPath := filepath.Join(tmp, "token")
	aclsPath := filepath.Join(tmp, "acls.json")

	// Two ACLs: Read + Describe → maps to DeveloperRead.
	const aclsJSON = `{
  "schema_version": "1",
  "source": {"type": "json", "generated_at": "2026-05-24T00:00:00Z"},
  "acls": [
    {"id": 1, "principal": "User:alice", "host": "*", "operation": "Read",     "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"},
    {"id": 2, "principal": "User:alice", "host": "*", "operation": "Describe", "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"}
  ]
}`
	if err := os.WriteFile(aclsPath, []byte(aclsJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("fake-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Build a valid plan.json.
	if exit := cli.Execute([]string{
		"plan",
		"--acls", aclsPath,
		"--scopes", scopesPath,
		"--out", planPath,
	}); exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}

	// Remove acls.json so the run dir no longer has it.
	if err := os.Remove(aclsPath); err != nil {
		t.Fatal(err)
	}

	exit := cli.Execute([]string{
		"verify",
		"--plan", planPath,
		"--mode", "effective",
		"--mds-url", srv.URL,
		"--mds-token-file", tokenPath,
	})
	if exit == 0 {
		t.Error("expected non-zero exit when acls.json is absent; got 0")
	}
}
