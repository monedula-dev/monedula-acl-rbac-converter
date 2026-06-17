// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package common_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/shell"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

func TestHeader_StartsWithShebangAndStrictMode(t *testing.T) {
	got := common.BuildScriptHeader(common.HeaderInputs{
		ToolVersion:      "v1.0.0",
		GeneratedAt:      time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
		PlanSHA256:       "abc123",
		VerifySHA256:     "def456",
		BootstrapServers: "kafka.example.com:9093",
		CommandConfig:    "/etc/kafka/admin.properties",
		MDSURL:           "https://mds.example.com",
		Principals:       []string{"User:alice", "User:bob"},
		RunDir:           "/abs/path/runs/2026-05-21T10-00-00Z",
	})
	lines := strings.Split(got, "\n")
	if lines[0] != "#!/usr/bin/env bash" {
		t.Errorf("first line: %q", lines[0])
	}
	if lines[1] != "set -euo pipefail" {
		t.Errorf("second line: %q", lines[1])
	}
	if !strings.Contains(got, "plan.sha256 = abc123") {
		t.Errorf("missing plan checksum")
	}
	if !strings.Contains(got, "User:alice") {
		t.Errorf("missing principal list")
	}
	if !strings.Contains(got, "/abs/path/runs/") {
		t.Errorf("missing absolute run dir")
	}
}

// TestHeader_EmitsRuntimePlanSHA256Guard is the B13 / P1 regression guard:
// the generated script must refuse to run if plan.json was edited after
// generation. The header emits an EXPECTED_PLAN_SHA256 / ACTUAL_PLAN_SHA256
// compare that exits 5 on mismatch — and, fail-closed, also exits 5 when
// plan.json cannot be hashed at all — with a single documented override
// (MONEDULA_SKIP_PLAN_HASH_CHECK=1). The run-dir plan.json path is
// shell-quoted and fed on STDIN (GNU coreutils backslash-escape avoidance).
func TestHeader_EmitsRuntimePlanSHA256Guard(t *testing.T) {
	runDir := "/abs/runs/2026-05-21T10-00-00Z"
	got := common.BuildScriptHeader(common.HeaderInputs{
		ToolVersion: "v1.0.0",
		GeneratedAt: time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
		PlanSHA256:  "f491c57fb1df655249a459e56aaaf118146ef1946a847dc14b84d10ccebeda77",
		RunDir:      runDir,
	})
	// The plan.json path is joined with the OS separator (consistent with
	// the rest of the run-dir path handling in the script header).
	planPath := filepath.Join(runDir, "plan.json")
	for _, want := range []string{
		"EXPECTED_PLAN_SHA256='f491c57fb1df655249a459e56aaaf118146ef1946a847dc14b84d10ccebeda77'",
		// Documented override branch, evaluated before any hashing.
		`if [ "${MONEDULA_SKIP_PLAN_HASH_CHECK:-}" = "1" ]; then`,
		// Portable hash fed on STDIN (sha256sum (Linux) || shasum -a 256
		// (macOS) || true so the substitution can't trip set -e before the
		// emptiness test drives the explicit refusal).
		"ACTUAL_PLAN_SHA256=\"$( { sha256sum < '" + planPath + "' 2>/dev/null || shasum -a 256 < '" + planPath + "' 2>/dev/null || true; } | awk '{print $1}')\"",
		// Fail-closed: empty hash => refuse (exit 5) with the override hint.
		`if [ -z "$ACTUAL_PLAN_SHA256" ]; then`,
		"Set MONEDULA_SKIP_PLAN_HASH_CHECK=1 to override.",
		`elif [ "$EXPECTED_PLAN_SHA256" != "$ACTUAL_PLAN_SHA256" ]; then`,
		"exit 5",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("header missing runtime guard fragment %q\n---\n%s", want, got)
		}
	}
	// Fail-closed contract: the old fail-open "skipping integrity check"
	// wording (which let a missing tool / unreadable plan pass) must be gone.
	if strings.Contains(got, "skipping integrity check") {
		t.Errorf("guard must be fail-closed; found fail-open skip wording:\n%s", got)
	}
}

// TestHeader_RuntimeGuard_Executes runs the emitted guard through real bash to
// prove the fail-closed contract holds in practice, not just in the generated
// text (the "test the intent, not the oracle" lesson). It asserts: matching
// hash passes (exit 0); a tampered plan.json is refused (exit 5); a missing
// plan.json is ALSO refused (exit 5, fail-closed); and the documented override
// (MONEDULA_SKIP_PLAN_HASH_CHECK=1) skips the check (exit 0) even when tampered.
//
// Linux-gated: the header embeds an absolute run-dir path, and on Windows that
// is a backslash path that Cygwin/Git-Bash redirections handle inconsistently.
// The guard logic is platform-independent; running it on Linux (CI's platform)
// is sufficient and avoids that flakiness.
func TestHeader_RuntimeGuard_Executes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("embeds an absolute run-dir path; backslash paths under Cygwin bash redirection are unreliable — runs on Linux CI")
	}
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not on PATH")
	}

	runDir := t.TempDir()
	planPath := filepath.Join(runDir, "plan.json")
	content := []byte(`{"schema_version":"1"}` + "\n")
	if err := os.WriteFile(planPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	expected := hex.EncodeToString(sum[:])

	header := common.BuildScriptHeader(common.HeaderInputs{
		ToolVersion: "test",
		GeneratedAt: time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
		PlanSHA256:  expected,
		RunDir:      runDir,
	})
	scriptPath := filepath.Join(runDir, "header.sh")
	if err := os.WriteFile(scriptPath, []byte(header), 0o755); err != nil {
		t.Fatal(err)
	}

	run := func(env ...string) int {
		cmd := exec.Command(bashPath, scriptPath)
		cmd.Env = append(os.Environ(), env...)
		runErr := cmd.Run()
		if runErr == nil {
			return 0
		}
		if ee, ok := runErr.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		t.Fatalf("running guard script: %v", runErr)
		return -1
	}

	if code := run(); code != 0 {
		t.Errorf("matching hash should pass the guard (exit 0), got %d", code)
	}

	// Tamper plan.json: the recorded EXPECTED no longer matches.
	if err := os.WriteFile(planPath, []byte(`{"schema_version":"1","tampered":true}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run(); code != 5 {
		t.Errorf("tampered plan.json must be refused (exit 5), got %d", code)
	}
	if code := run("MONEDULA_SKIP_PLAN_HASH_CHECK=1"); code != 0 {
		t.Errorf("override must skip the check (exit 0) even when tampered, got %d", code)
	}

	// Missing plan.json: cannot hash -> fail-closed refusal, NOT a silent pass.
	if err := os.Remove(planPath); err != nil {
		t.Fatal(err)
	}
	if code := run(); code != 5 {
		t.Errorf("unhashable (missing) plan.json must fail closed (exit 5), got %d", code)
	}
	if code := run("MONEDULA_SKIP_PLAN_HASH_CHECK=1"); code != 0 {
		t.Errorf("override must skip even when plan.json is missing (exit 0), got %d", code)
	}
}

// TestHeader_EarlyExitSetup_SurvivesSpacesInPath is the regression guard for
// the trap-quoting fix. The previous design wrapped EarlyCleanupTrap in
// `trap '<it>' EXIT`, so a shell.Quote'd path containing a space closed the
// outer single quote early and split the trap into two arguments — leaving
// runtime.env behind on the very early-exit paths the trap was supposed to
// cover. The new design (verbatim block: `VAR='<path>'` assignment + trap
// referencing "$VAR") survives spaces.
//
// Linux-gated for the same reason as TestHeader_RuntimeGuard_Executes:
// needs real bash, and the run-dir absolute path is the input under test.
func TestHeader_EarlyExitSetup_SurvivesSpacesInPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires bash + Unix filesystem semantics; runs on Linux CI")
	}
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not on PATH")
	}

	// A run directory with a deliberate space — exactly the shape that would
	// have split the old `trap '...'` wrapper on the outer single quotes.
	runDir := filepath.Join(t.TempDir(), "run dir with space")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(runDir, "runtime.env")
	if err := os.WriteFile(envFile, []byte("dummy\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	earlySetup := "__T_RUNTIME_ENV=" + shell.Quote(envFile) + "\n" +
		`trap 'rm -f "$__T_RUNTIME_ENV"' EXIT`

	header := common.BuildScriptHeader(common.HeaderInputs{
		ToolVersion:    "test",
		GeneratedAt:    time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
		EarlyExitSetup: earlySetup,
	})

	scriptPath := filepath.Join(runDir, "header.sh")
	if err := os.WriteFile(scriptPath, []byte(header), 0o755); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command(bashPath, scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("script failed (the bug: trap split on the run-dir space): %v\nemitted header:\n%s\noutput:\n%s",
			err, header, out)
	}

	if _, err := os.Stat(envFile); err == nil {
		t.Errorf("runtime.env should have been removed by the EXIT trap even though the run-dir path contains a space; it still exists at %s\nemitted header:\n%s",
			envFile, header)
	}
}

// TestHeader_EarlyExitSetup_ReportsTriggeringExitCode is the regression guard
// for the trap's `$?` ordering: bash overwrites `$?` after every command run
// inside the trap, so a trap that does `rm -f ...; printf "...exit %d..." "$?"`
// reports `rm`'s exit (almost always 0), NOT the failure that triggered EXIT.
// The fix captures `rc=$?` as the FIRST statement in the trap and references
// `"$rc"` from printf. This test writes a script that ends with `exit 5` and
// asserts the trap-emitted message reports `(exit 5)`.
//
// Linux-gated: requires real bash to observe the trap behaviour.
func TestHeader_EarlyExitSetup_ReportsTriggeringExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires bash to observe trap exit-code propagation; runs on Linux CI")
	}
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not on PATH")
	}

	runDir := t.TempDir()
	envFile := filepath.Join(runDir, "runtime.env")
	if err := os.WriteFile(envFile, []byte("dummy\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Mirror the production trap shape from delete/deny/script.go: capture
	// rc first, THEN run cleanup, THEN print using $rc.
	earlySetup := "__T_RUNTIME_ENV=" + shell.Quote(envFile) + "\n" +
		`trap 'rc=$?; rm -f "$__T_RUNTIME_ENV"; printf "delete-deny-acls.sh complete (exit %d)\n" "$rc" >&2' EXIT`

	header := common.BuildScriptHeader(common.HeaderInputs{
		ToolVersion:    "test",
		GeneratedAt:    time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
		EarlyExitSetup: earlySetup,
	})

	scriptPath := filepath.Join(runDir, "header.sh")
	// Append `exit 5` after the header to force a non-zero termination. The
	// trap must report 5, not 0.
	body := header + "exit 5\n"
	if err := os.WriteFile(scriptPath, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bashPath, scriptPath)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// The script must have exited 5 (the trap fires AFTER exit and inherits
	// the status; bash propagates the trigger's code unless the trap calls
	// `exit` itself).
	ee, ok := runErr.(*exec.ExitError)
	if !ok || ee.ExitCode() != 5 {
		t.Fatalf("expected script to exit 5, got: %v\nstderr:\n%s", runErr, stderr.String())
	}
	if !strings.Contains(stderr.String(), "delete-deny-acls.sh complete (exit 5)") {
		t.Errorf("trap must report the TRIGGER's exit code (5), not the cleanup command's $?; stderr was:\n%s",
			stderr.String())
	}
	// Negative assertion: the previous-buggy trap would have logged exit 0
	// (the success of `rm -f`). Make that explicit so a regression is obvious.
	if strings.Contains(stderr.String(), "complete (exit 0)") {
		t.Errorf("trap reported exit 0 — the bug returned: $? was clobbered by `rm` before printf; stderr:\n%s",
			stderr.String())
	}
}

// TestHeader_SanitisesControlCharsInComments is the defence-in-depth
// regression guard for the "newline-in-comment-header" injection class.
// types.ValidateACLSet rejects ACL rows with control chars upstream, but
// BootstrapServers / MDSURL / RunDir / Principals all flow into header
// comment lines as `%s`. A '\n' in any of them would have escaped the `#`
// comment and run as bash at script-execution time, BEFORE any guard or
// trap fired. The header must replace control characters with '?' so every
// comment stays on a single line regardless of input.
func TestHeader_SanitisesControlCharsInComments(t *testing.T) {
	got := common.BuildScriptHeader(common.HeaderInputs{
		ToolVersion:      "v1.0.0",
		GeneratedAt:      time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
		BootstrapServers: "kafka.example.com:9093\necho pwned",
		MDSURL:           "https://mds.example.com\nrm -rf /",
		Principals:       []string{"User:alice", "User:eve\necho pwned"},
		RunDir:           "/runs/legit\nmalicious",
	})

	// Negative assertions: NONE of the injected payloads may appear on a
	// line of their own (i.e. preceded by a real newline) — that would mean
	// the '\n' survived into the emitted script as a real line break.
	for _, payload := range []string{
		"\necho pwned",
		"\nrm -rf /",
		"\nmalicious",
	} {
		if strings.Contains(got, payload) {
			t.Errorf("control-char payload %q survived into header — comment injection:\n%s", payload, got)
		}
	}
	// Positive assertions: the printable parts of each tainted field are
	// still present (so the header still identifies the value), with control
	// chars replaced by '?'.
	for _, want := range []string{
		"# bootstrap-server: kafka.example.com:9093?echo pwned",
		"# mds-url: https://mds.example.com?rm -rf /",
		"#   User:eve?echo pwned",
		"# Run directory (absolute): /runs/legit?malicious",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected sanitised line %q in header; got:\n%s", want, got)
		}
	}
}

// TestHeader_NoGuardWithoutPlanSHA256 confirms the guard is omitted when
// no plan SHA-256 is available (e.g. a degenerate caller), so we never
// emit a half-formed compare against an empty EXPECTED value.
func TestHeader_NoGuardWithoutPlanSHA256(t *testing.T) {
	got := common.BuildScriptHeader(common.HeaderInputs{
		ToolVersion: "v1.0.0",
		GeneratedAt: time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
		RunDir:      "/abs/runs/x",
		// PlanSHA256 intentionally empty
	})
	if strings.Contains(got, "EXPECTED_PLAN_SHA256") {
		t.Errorf("guard should be omitted when PlanSHA256 is empty:\n%s", got)
	}
}

func TestRuntimeEnv_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := common.RuntimeEnv{
		BootstrapServers:   "kafka.example.com:9093",
		CommandConfig:      "/etc/kafka/admin.properties",
		MDSURL:             "https://mds.example.com",
		MDSTokenFile:       "/etc/secrets/mds-token",
		InsecureSkipVerify: true,
		MaxRetries:         7,
		AuthToken:          "secret-per-run-token",
	}

	path, err := common.WriteRuntimeEnv(dir, in)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if filepath.Base(path) != "runtime.env" {
		t.Errorf("filename: %q", path)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != 0o600 {
			t.Errorf("mode: got %v, want 0600", info.Mode().Perm())
		}
	}

	got, err := common.ReadRuntimeEnv(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.BootstrapServers != "kafka.example.com:9093" || got.AuthToken != "secret-per-run-token" {
		t.Errorf("round trip: got %+v", got)
	}
	// P2a: the TLS posture and retry tuning the operator chose at
	// generation time must survive into runtime.env, otherwise the
	// per-ACL delete-deny-one re-check silently reverts to secure-verify /
	// default retries at script-execution time.
	if !got.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify did not round-trip; got %+v", got)
	}
	if got.MaxRetries != 7 {
		t.Errorf("MaxRetries: got %d, want 7", got.MaxRetries)
	}
}

// TestRuntimeEnv_BoolSerialization pins the on-disk encoding of the two
// scalar fields P2a added. The writer must emit shell-sourceable
// MDS_INSECURE_SKIP_VERIFY=true|false and MDS_MAX_RETRIES=N lines, and the
// reader must parse the boolean leniently (true/1/yes -> true).
func TestRuntimeEnv_BoolSerialization(t *testing.T) {
	dir := t.TempDir()
	if _, err := common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		MDSURL:             "https://mds.example.com",
		InsecureSkipVerify: false,
		MaxRetries:         0,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "runtime.env"))
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "MDS_INSECURE_SKIP_VERIFY=false\n") {
		t.Errorf("expected MDS_INSECURE_SKIP_VERIFY=false line; got:\n%s", body)
	}
	if !strings.Contains(body, "MDS_MAX_RETRIES=0\n") {
		t.Errorf("expected MDS_MAX_RETRIES=0 line; got:\n%s", body)
	}

	// Lenient boolean parse: hand-edited 1/yes should read as true.
	for _, truthy := range []string{"true", "1", "yes"} {
		envBody := "MDS_URL='https://mds.example.com'\nMDS_INSECURE_SKIP_VERIFY=" + truthy + "\nMDS_MAX_RETRIES=4\n"
		d2 := t.TempDir()
		if err := os.WriteFile(filepath.Join(d2, "runtime.env"), []byte(envBody), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := common.ReadRuntimeEnv(d2)
		if err != nil {
			t.Fatalf("read %q: %v", truthy, err)
		}
		if !got.InsecureSkipVerify {
			t.Errorf("value %q should parse as true; got %+v", truthy, got)
		}
		if got.MaxRetries != 4 {
			t.Errorf("value %q: MaxRetries got %d, want 4", truthy, got.MaxRetries)
		}
	}
}

func TestNewAuthToken_Random(t *testing.T) {
	t1 := common.NewAuthToken()
	t2 := common.NewAuthToken()
	if t1 == t2 {
		t.Errorf("tokens should be random; got identical values")
	}
	if len(t1) < 32 {
		t.Errorf("token too short: %q", t1)
	}
}

func TestEligible_PrincipalFilterIncluded(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{
		{ID: "rb-aaaaaaaaaaaa", Principal: "User:alice", SourceACLIDs: []int{1, 2}},
		{ID: "rb-bbbbbbbbbbbb", Principal: "User:bob", SourceACLIDs: []int{3}},
	}}
	verifyRes := []verify.Result{
		{BindingID: "rb-aaaaaaaaaaaa", Status: verify.StatusEffectiveOK},
		{BindingID: "rb-bbbbbbbbbbbb", Status: verify.StatusEffectiveOK},
	}
	eligible := common.EligibleACLs(common.EligibilityInputs{
		Plan:       plan,
		Verify:     verifyRes,
		Principals: []string{"User:alice"},
	})
	if len(eligible) != 2 {
		t.Errorf("got %d ACL ids, want 2 (alice's two)", len(eligible))
	}
}

func TestEligible_MissingBindingExcluded(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{
		{ID: "rb-aaaaaaaaaaaa", Principal: "User:alice", SourceACLIDs: []int{1}},
	}}
	verifyRes := []verify.Result{
		{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 1, Status: verify.StatusEffectiveMissing},
	}
	eligible := common.EligibleACLs(common.EligibilityInputs{
		Plan:       plan,
		Verify:     verifyRes,
		Principals: []string{"User:alice"},
	})
	if len(eligible) != 0 {
		t.Errorf("got %d, want 0 (EFFECTIVE_MISSING)", len(eligible))
	}
}

// TestEligible_EffectiveModePerSourceACL pins the safety contract: with
// effective-mode verify rows keyed on (binding_id, source_acl_id), only
// the source ACLs whose own row is EFFECTIVE_OK are eligible. Sibling
// EFFECTIVE_MISSING / EFFECTIVE_UNKNOWN source ACLs under the same
// binding MUST NOT be promoted to eligible just because a peer is OK.
// Regression for spec §4.3 + README "Step 5".
func TestEligible_EffectiveModePerSourceACL(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{
		{ID: "rb-aaaaaaaaaaaa", Principal: "User:alice", SourceACLIDs: []int{1, 2, 3}},
	}}
	verifyRes := []verify.Result{
		{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 1, Status: verify.StatusEffectiveOK},
		{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 2, Status: verify.StatusEffectiveMissing},
		{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 3, Status: verify.StatusEffectiveUnknown},
	}
	eligible := common.EligibleACLs(common.EligibilityInputs{
		Plan:       plan,
		Verify:     verifyRes,
		Principals: []string{"User:alice"},
	})
	if len(eligible) != 1 || eligible[0] != 1 {
		t.Errorf("got %v, want [1] (only the EFFECTIVE_OK source ACL)", eligible)
	}
}

// TestEligible_BindingsExistModeStillCovers preserves the coarser
// contract for `verify --mode bindings-exist`: those rows have a
// BindingID but SourceACLID == 0, and they vouch for every source
// ACL on the binding. Operators opt into this grain by passing the
// flag, so the eligibility check must continue to honour it.
func TestEligible_BindingsExistModeStillCovers(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{
		{ID: "rb-aaaaaaaaaaaa", Principal: "User:alice", SourceACLIDs: []int{1, 2, 3}},
	}}
	verifyRes := []verify.Result{
		{BindingID: "rb-aaaaaaaaaaaa", Status: verify.StatusBindingExists},
	}
	eligible := common.EligibleACLs(common.EligibilityInputs{
		Plan:       plan,
		Verify:     verifyRes,
		Principals: []string{"User:alice"},
	})
	if len(eligible) != 3 {
		t.Errorf("got %v, want all 3 (binding-level BINDING_EXISTS covers every source ACL)", eligible)
	}
}

// TestEligible_DuplicateRowsNonAcceptableWins is the B8 regression guard:
// if verify.json carries the same (binding_id, source_acl_id) pair twice —
// once acceptable, once not — the ACL must NOT be eligible regardless of
// row ordering in the file. A naive last-write-wins map let a trailing
// OK row silently overwrite an earlier MISSING.
func TestEligible_DuplicateRowsNonAcceptableWins(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{
		{ID: "rb-aaaaaaaaaaaa", Principal: "User:alice", SourceACLIDs: []int{1}},
	}}

	cases := []struct {
		name    string
		results []verify.Result
	}{
		{
			name: "OK then MISSING",
			results: []verify.Result{
				{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 1, Status: verify.StatusEffectiveOK},
				{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 1, Status: verify.StatusEffectiveMissing},
			},
		},
		{
			name: "MISSING then OK",
			results: []verify.Result{
				{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 1, Status: verify.StatusEffectiveMissing},
				{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 1, Status: verify.StatusEffectiveOK},
			},
		},
		{
			name: "OK then UNKNOWN",
			results: []verify.Result{
				{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 1, Status: verify.StatusEffectiveOK},
				{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 1, Status: verify.StatusEffectiveUnknown},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eligible := common.EligibleACLs(common.EligibilityInputs{
				Plan:       plan,
				Verify:     tc.results,
				Principals: []string{"User:alice"},
			})
			if len(eligible) != 0 {
				t.Errorf("got %v, want [] (a non-acceptable duplicate must veto eligibility)", eligible)
			}
		})
	}
}

// TestEligible_DuplicateRowsAllAcceptable confirms the dedupe does not
// over-reject: two acceptable rows for the same pair still leave it
// eligible.
func TestEligible_DuplicateRowsAllAcceptable(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{
		{ID: "rb-aaaaaaaaaaaa", Principal: "User:alice", SourceACLIDs: []int{1}},
	}}
	verifyRes := []verify.Result{
		{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 1, Status: verify.StatusEffectiveOK},
		{BindingID: "rb-aaaaaaaaaaaa", SourceACLID: 1, Status: verify.StatusEffectiveOK},
	}
	eligible := common.EligibleACLs(common.EligibilityInputs{
		Plan:       plan,
		Verify:     verifyRes,
		Principals: []string{"User:alice"},
	})
	if len(eligible) != 1 || eligible[0] != 1 {
		t.Errorf("got %v, want [1] (two acceptable rows keep the pair eligible)", eligible)
	}
}
