// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

// fileSHA256ForTest returns the hex SHA-256 of a file, matching
// common.FileSHA256 / the value verify stamps into plan_sha256.
func fileSHA256ForTest(t *testing.T, path string) (string, error) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// readVerify is exercised end-to-end by tests/integration/full_pipeline_test.go,
// but a focused unit test guards against silent serialisation drift in
// verify.Result (which delete-acls + delete-deny-acls depend on).

// TestReadVerify_Envelope exercises the envelope shape that
// `verify.Run` writes to disk. Mirrors what `verify --format json`
// emits on stdout: `{results: [...], counts: {...}}`.
func TestReadVerify_Envelope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verify.json")
	body := `{
		"results": [
			{"binding_id":"rb-aaaaaaaaaaaa","source_acl_id":1,"status":"EFFECTIVE_OK"},
			{"binding_id":"rb-aaaaaaaaaaaa","source_acl_id":2,"status":"EFFECTIVE_OK"},
			{"binding_id":"rb-bbbbbbbbbbbb","source_acl_id":3,"status":"EFFECTIVE_MISSING","detail":"LDAP did not resolve principal"}
		],
		"counts": {"total": 3, "effective_ok": 2, "effective_missing": 1, "effective_unknown": 0}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readVerify(path)
	if err != nil {
		t.Fatalf("readVerify: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 results; got %d", len(got))
	}
	if got[0].Status != verify.StatusEffectiveOK {
		t.Errorf("first row status: got %q want %q", got[0].Status, verify.StatusEffectiveOK)
	}
	if got[2].Status != verify.StatusEffectiveMissing {
		t.Errorf("third row status: got %q want %q", got[2].Status, verify.StatusEffectiveMissing)
	}
	if got[2].Detail == "" {
		t.Errorf("third row detail should preserve LDAP message")
	}
}

// TestReadVerify_BareArrayRejected asserts that a bare `[]Result`
// verify.json (any earlier dev-build shape) is rejected with a clear
// re-run-verify message instead of silently decoding.
func TestReadVerify_BareArrayRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verify.json")
	body := `[
		{"binding_id":"rb-aaaaaaaaaaaa","source_acl_id":1,"status":"EFFECTIVE_OK"}
	]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readVerify(path)
	if err == nil {
		t.Fatal("expected error reading bare-array verify.json")
	}
	if !strings.Contains(err.Error(), "verify") {
		t.Errorf("error should mention verify; got: %v", err)
	}
}

// TestCheckVerifyBoundToPlan_MismatchRefused is the B4 regression guard:
// a verify.json whose stamped plan_sha256 came from a *different* plan
// must be refused by delete-* before any destructive work. Mixing
// plan2's bytes with verify1's stamp (computed against plan1) must error
// with both hashes named.
func TestCheckVerifyBoundToPlan_MismatchRefused(t *testing.T) {
	dir := t.TempDir()
	// plan2 on disk; verify.json stamped with a hash that does not match.
	plan2 := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(plan2, []byte(`{"schema_version":"1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const verify1SHA = "1111111111111111111111111111111111111111111111111111111111111111"
	err := checkVerifyBoundToPlan(verify1SHA, plan2)
	if err == nil {
		t.Fatal("expected refusal for verify.json bound to a different plan")
	}
	if !strings.Contains(err.Error(), "different plan") {
		t.Errorf("error should explain the mismatch; got: %v", err)
	}
	if !strings.Contains(err.Error(), verify1SHA) {
		t.Errorf("error should name the verify plan_sha256; got: %v", err)
	}
}

// TestCheckVerifyBoundToPlan_MatchAccepted confirms the happy path: a
// verify.json stamped with the hash of the plan being deleted passes.
func TestCheckVerifyBoundToPlan_MatchAccepted(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(planPath, []byte(`{"schema_version":"1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sha, err := fileSHA256ForTest(t, planPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkVerifyBoundToPlan(sha, planPath); err != nil {
		t.Errorf("matching plan_sha256 must be accepted; got: %v", err)
	}
}

// TestCheckVerifyBoundToPlan_MissingRefused asserts an empty plan_sha256
// (an old verify.json from before the field existed) is refused.
func TestCheckVerifyBoundToPlan_MissingRefused(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(planPath, []byte(`{"schema_version":"1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkVerifyBoundToPlan("", planPath); err == nil {
		t.Fatal("expected refusal for verify.json missing plan_sha256")
	}
}

func TestReadVerify_FileMissing(t *testing.T) {
	_, err := readVerify(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected error reading missing file")
	}
}

func TestReadVerify_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verify.json")
	if err := os.WriteFile(path, []byte(`{not valid json`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readVerify(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
	// Wrapped error must mention verify.json so operators know where to look.
	if !strings.Contains(err.Error(), "verify.json") {
		t.Errorf("error should mention verify.json; got: %v", err)
	}
}
