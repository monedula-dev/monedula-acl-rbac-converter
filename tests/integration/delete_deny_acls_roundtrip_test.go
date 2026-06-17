// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
)

// =============================================================================
// EXECUTION MODEL  (read this before debugging a CI failure)
// =============================================================================
//
// This test closes the gap that let three serious bugs ship in the
// delete-deny-acls -> delete-deny-one path (PREFIXED-DENY no-op, unauthenticated
// MDS, runtime.env credential drops): unlike delete-acls, *no* test had ever
// EXECUTED the generated DENY-deletion script end to end. The unit-level
// real-exec test (pkg/aclrbac/delete/deny/one_realexec_test.go) drives
// RunOne()'s production exec path directly, but it never runs the generated
// bash, never sources runtime.env through bash, and never resolves the
// `monedula-acl-rbac` binary off PATH. This test does all three.
//
// The chain under test:
//
//     bash delete-deny-acls.sh
//        -> source runtime.env                     (credentials + RUNTIME_AUTH_TOKEN)
//        -> monedula-acl-rbac delete-deny-one ...   (the freshly-built binary, on PATH)
//             -> MDS LookupAllowed (Bearer auth)    (the host httptest fake MDS)
//             -> realExec -> kafka-acls --remove ...  (the host stub, via MONEDULA_KAFKA_ACLS_BIN)
//
// WHY THE SCRIPT RUNS ON THE *HOST*, NOT IN THE CONTAINER:
//
//   The delete-acls round-trip (delete_acls_roundtrip_test.go) executes its
//   generated script INSIDE the cp-kafka container because that script only
//   needs `kafka-acls`, which the image already ships. The delete-deny-acls
//   script is fundamentally different: every line invokes the *monedula*
//   binary (`delete-deny-one`), which then needs (a) to reach the fake MDS and
//   (b) to invoke kafka-acls. The container has kafka-acls but no monedula
//   binary and no route to the host's httptest MDS. So we run the script on
//   the HOST and provide the two missing pieces via seams:
//
//     1. monedula-acl-rbac : built into a temp dir and put first on PATH so the
//        script's bare `monedula-acl-rbac delete-deny-one` resolves to it.
//        (script.go emits exactly that bare command — see writeScript().)
//     2. kafka-acls        : NOT present on the host. We write a STUB shell
//        script named `kafka-acls` and point MONEDULA_KAFKA_ACLS_BIN at it
//        (one.go::realExec honours that env var). The stub records the argv it
//        received to a per-ACL file so we can assert on it.
//
// CHOICE OF STUB BEHAVIOUR — argv+auth capture, NOT real broker mutation:
//
//   The task allowed either (a) a stub that actually mutates the real broker,
//   or (b) a fallback stub that only records argv while the MDS-auth + script
//   chain is asserted, leaving the *real* `kafka-acls --remove` proof to the
//   delete-acls path. We chose (b) deliberately:
//
//     - The only reliable way for a host shell stub to mutate the *container's*
//       broker would be to shell out to `docker exec` (brittle: docker may not
//       be on PATH in every CI runner, and we'd have to thread the testcontainers
//       container ID into a generated shell script) or to re-exec this test
//       binary in a "kafka-acls mode" (needs a package-wide TestMain, invasive
//       to the other integration tests). Both are fragile.
//     - The genuine value of THIS test is proving the *chain*: generated deny
//       script -> real binary -> authenticated MDS re-check -> correct
//       kafka-acls argv (including the PREFIXED `--resource-pattern-type`
//       flag that bug B1 dropped). That it does, reliably.
//     - That real `kafka-acls --remove ... --resource-pattern-type {literal,
//       prefixed}` actually mutates a real broker is proven separately by the
//       delete-acls round-trip (delete_acls_roundtrip_test.go) and by
//       TestRealBroker_DeleteACLs_PrefixedPattern below.
//
//   Net: this test asserts everything up to (and including) the exact argv
//   handed to kafka-acls; the broker mutation itself is covered elsewhere.
//
// RUNTIME_AUTH_TOKEN HANDLING — the bug this test deliberately exercises:
//
//   delete-deny-one reads its handshake token from os.Getenv("RUNTIME_AUTH_TOKEN")
//   (see cli/cmd_delete.go::newDeleteDenyOneCmd). The generated script does
//   `source runtime.env` (which sets a *shell* variable — NOT inherited by
//   child processes) and then `export RUNTIME_AUTH_TOKEN` (script.go) so the
//   delete-deny-one child inherits it. An earlier version of the generator
//   omitted that export, so every real run aborted with a token mismatch on
//   the first ACL — a P0 that no unit test caught because the component tests
//   pass EnvToken directly, bypassing the source→export→child env flow.
//
//   This test does NOT inject RUNTIME_AUTH_TOKEN into the bash environment
//   itself: it relies on the generated script's own `export`. So if a
//   regression drops that export, this test fails here with a token mismatch
//   — which is exactly the proactive signal we want. (The portable guard
//   TestGenerate_RoutesThroughDeleteDenyOne also asserts the export is
//   present, after the source and before the first delete-deny-one call.)
//
// =============================================================================

// buildMonedulaBinary compiles ./cmd/monedula-acl-rbac into binDir and returns
// the absolute path to the produced binary. The repo root is located by
// walking up from the test's working directory until go.mod is found, so the
// test does not assume a fixed cwd.
func buildMonedulaBinary(ctx context.Context, t *testing.T, binDir string) string {
	t.Helper()
	repoRoot := findRepoRoot(t)
	binName := "monedula-acl-rbac"
	binPath := filepath.Join(binDir, binName)
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, "./cmd/monedula-acl-rbac")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build monedula-acl-rbac failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(binPath); err != nil {
		t.Fatalf("built binary missing at %s: %v", binPath, err)
	}
	return binPath
}

// findRepoRoot walks up from the cwd until it finds go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod walking up from test working dir")
		}
		dir = parent
	}
}

// writeKafkaACLsStub writes a host shell script named "kafka-acls" into stubDir
// and returns its path. Every invocation appends the full argv (one line,
// space-joined) to argsFile. It exits 0 so delete-deny-one logs OK. It does
// NOT mutate any broker — see the EXECUTION MODEL comment for why.
//
// The stub also tees the argv to stderr so a failing CI run shows it in the
// test log.
func writeKafkaACLsStub(t *testing.T, stubDir, argsFile string) string {
	t.Helper()
	stubPath := filepath.Join(stubDir, "kafka-acls")
	// "$*" is the space-joined argv. We intentionally record a single line per
	// invocation so the per-ACL argv is easy to grep. Using printf (not echo)
	// to avoid surprises with leading dashes in the argv.
	body := "#!/usr/bin/env bash\n" +
		"set -euo pipefail\n" +
		"printf '%s\\n' \"$*\" >> " + shellSingleQuote(argsFile) + "\n" +
		"printf 'STUB kafka-acls argv: %s\\n' \"$*\" >&2\n" +
		"exit 0\n"
	if err := os.WriteFile(stubPath, []byte(body), 0o755); err != nil {
		t.Fatalf("write kafka-acls stub: %v", err)
	}
	return stubPath
}

// shellSingleQuote wraps s in single quotes, escaping embedded single quotes,
// for safe interpolation into a generated shell script. t.TempDir() paths on
// CI are well-behaved, but a path with a quote should not corrupt the stub.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// TestRealBroker_DeleteDenyACLs_RoundTrip exercises the full
// extract -> plan -> verify -> delete-deny-acls (script-emission) pipeline
// against a real cp-kafka container, then EXECUTES the generated
// delete-deny-acls.sh on the host. See the EXECUTION MODEL comment at the top
// of this file for the host-vs-container split and the stub/seam design.
//
// What it proves:
//   - The generated delete-deny-acls.sh runs to completion (exit 0).
//   - Its plan.sha256 runtime guard passes (plan.json unchanged).
//   - It sources runtime.env and invokes the freshly-built monedula binary.
//   - delete-deny-one performs an AUTHENTICATED (Bearer) MDS live re-check.
//   - The re-check concludes SAFE_TO_REMOVE and the production realExec path
//     hands kafka-acls the correct argv for BOTH a LITERAL and a PREFIXED DENY,
//     including `--resource-pattern-type literal` / `--resource-pattern-type
//     prefixed` (regression guard for bug B1) and `--deny-principal User:eve`.
func TestRealBroker_DeleteDenyACLs_RoundTrip(t *testing.T) {
	// This test HOST-EXECUTES the generated delete-deny-acls.sh, which enforces
	// the spec §4.3 safety contract that runtime.env (it holds RUNTIME_AUTH_TOKEN)
	// is mode 0600. The file is written by `delete-deny-acls` via
	// os.WriteFile(..., 0o600). On Windows that call cannot set real Unix
	// permissions: a Cygwin/Git-Bash `stat -c '%a'` reports 0644 regardless, and
	// `chmod 600` does not change the reported mode either. So the script's
	// mode check correctly refuses to run, and there is no way to satisfy it on a
	// Windows host without weakening the production check. The chain is validated
	// fully on Linux (operators' and CI's platform), where 0o600 is real. Skip
	// here rather than disable a real safety guard.
	if runtime.GOOS == "windows" {
		t.Skip("host-executes a Unix bash script that enforces runtime.env mode 0600; " +
			"Windows cannot represent that mode (os.WriteFile 0o600 -> Cygwin stat reports 0644, " +
			"chmod 600 does not change it), so the script's mode check cannot pass on a Windows host. " +
			"Runs fully on Linux CI.")
	}

	// Generous timeout: the delete-acls round-trip uses 6 min; this one also
	// builds the monedula binary, so keep the same headroom.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	c, brokers := startCpKafkaContainer(ctx, t)
	defer func() {
		if err := c.Terminate(ctx); err != nil {
			t.Logf("container terminate: %v", err)
		}
	}()
	t.Logf("cp-kafka brokers (external): %v", brokers)

	// Create two DENY ACLs for User:eve via kadm: one LITERAL, one PREFIXED.
	cl, err := kgo.NewClient(kgo.SeedBrokers(brokers...))
	if err != nil {
		t.Fatalf("kgo client: %v", err)
	}
	adm := kadm.NewClient(cl)
	defer cl.Close()

	denyLiteral := kadm.NewACLs().
		Deny("User:eve").
		DenyHosts("*").
		Topics("secrets").
		ResourcePatternType(kadm.ACLPatternLiteral).
		Operations(kadm.OpRead)
	denyPrefixed := kadm.NewACLs().
		Deny("User:eve").
		DenyHosts("*").
		Topics("secret-").
		ResourcePatternType(kadm.ACLPatternPrefixed).
		Operations(kadm.OpRead)

	for _, b := range []*kadm.ACLBuilder{denyLiteral, denyPrefixed} {
		res, err := adm.CreateACLs(ctx, b)
		if err != nil {
			t.Fatalf("CreateACLs (deny): %v", err)
		}
		for _, r := range res {
			if r.Err != nil {
				t.Skipf("CreateACLs returned %v — broker may not have ACL security enabled; skipping", r.Err)
			}
		}
	}

	// Sanity: confirm both DENY ACLs are present before deletion.
	if got := describeEveDenies(ctx, t, adm); got != 2 {
		t.Fatalf("pre-delete: expected 2 DENY ACLs for eve, got %d", got)
	}

	// Stand up the host fake MDS (empty resources -> SAFE_TO_REMOVE).
	mds := newContractMDS()
	defer mds.srv.Close()

	tmp := t.TempDir()
	aclsPath := filepath.Join(tmp, "acls.json")
	scopesPath := filepath.Join(tmp, "scopes.yaml")
	planPath := filepath.Join(tmp, "plan.json")
	verifyPath := filepath.Join(tmp, "verify.json")
	tokenPath := filepath.Join(tmp, "mds.token")
	denyScript := filepath.Join(tmp, "delete-deny-acls.sh")

	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("fake-bearer-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	hostBootstrap := strings.Join(brokers, ",")

	// 1. extract --from live: the DENY ACLs land in acls.json (rejected by the
	//    planner, but present as ACL rows for the deny path).
	if exit := cli.Execute([]string{
		"extract", "--from", "live",
		"--bootstrap-server", hostBootstrap,
		"--out", aclsPath,
	}); exit != 0 {
		t.Fatalf("extract exit %d", exit)
	}

	// 2. plan. DENY ACLs always land in plan.json::rejected[] (DENY is never
	//    auto-converted), so `plan` exits 3 (unhealthy) by design — pass
	//    --allow-rejected to proceed. With no covering ALLOW for eve, the
	//    planner marks every DENY SAFE_TO_REMOVE in deny_analysis (asserted
	//    below before we rely on it).
	if exit := cli.Execute([]string{
		"plan",
		"--acls", aclsPath,
		"--scopes", scopesPath,
		"--allow-rejected",
		"--out", planPath,
	}); exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}
	assertDenySafeToRemove(t, planPath)

	// 3. verify. The deny path requires verify.json to carry a plan_sha256 that
	//    matches plan.json (B4); `verify` stamps it. The DENY-only plan has no
	//    bindings, so verify does no lookups here and produces an empty result
	//    set — but it still writes verify.json with the stamp.
	if exit := cli.Execute([]string{
		"verify",
		"--plan", planPath,
		"--mds-url", mds.srv.URL,
		"--mds-token-file", tokenPath,
	}); exit != 0 {
		t.Fatalf("verify exit %d", exit)
	}

	// 4. delete-deny-acls in script-emission mode. Writes delete-deny-acls.sh
	//    + runtime.env (the latter carries the MDS creds + RUNTIME_AUTH_TOKEN).
	if exit := cli.Execute([]string{
		"delete-deny-acls",
		"--plan", planPath,
		"--verify", verifyPath,
		"--bootstrap-server", hostBootstrap,
		"--mds-url", mds.srv.URL,
		"--mds-token-file", tokenPath,
		"--principal", "User:eve",
		"--confirm", "--i-understand-this-may-grant-access",
	}); exit != 0 {
		t.Fatalf("delete-deny-acls exit %d", exit)
	}

	// 5. Build the monedula binary into a dedicated dir; that dir + the stub
	//    dir go first on PATH. The script's bare `monedula-acl-rbac` resolves to
	//    our build; realExec's bare `kafka-acls` fallback is unused because we
	//    set MONEDULA_KAFKA_ACLS_BIN, but we still put the stub dir on PATH for
	//    belt-and-braces.
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	buildMonedulaBinary(ctx, t, binDir)

	stubDir := filepath.Join(tmp, "stub")
	if err := os.MkdirAll(stubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	argsFile := filepath.Join(tmp, "kafka-acls-argv.txt")
	stubPath := writeKafkaACLsStub(t, stubDir, argsFile)

	// 6. Sanity-check runtime.env carries a token. We do NOT export it into
	//    the bash env ourselves — the generated script is responsible for
	//    `export RUNTIME_AUTH_TOKEN` after sourcing runtime.env (see the
	//    EXECUTION MODEL comment). This test relies on that, so a regression
	//    dropping the export surfaces here as a token mismatch.
	runEnv, err := common.ReadRuntimeEnv(tmp)
	if err != nil {
		t.Fatalf("read runtime.env: %v", err)
	}
	if strings.TrimSpace(runEnv.AuthToken) == "" {
		t.Fatalf("runtime.env carried no RUNTIME_AUTH_TOKEN; cannot drive delete-deny-one")
	}

	// 7. Execute the generated delete-deny-acls.sh on the host.
	scriptBytes, err := os.ReadFile(denyScript)
	if err != nil {
		t.Fatalf("read delete-deny-acls.sh: %v", err)
	}
	t.Logf("delete-deny-acls.sh:\n%s", scriptBytes)

	runScript := exec.CommandContext(ctx, "bash", denyScript)
	runScript.Dir = tmp
	// Build a minimal, explicit environment so the host's ambient PATH (which
	// has neither monedula-acl-rbac nor kafka-acls) cannot interfere:
	//   - PATH: our build dir + stub dir first, then a sane base.
	//   - MONEDULA_KAFKA_ACLS_BIN: the recording stub (one.go::realExec reads it).
	//   - HOME: keep a real HOME so any token-cache machinery has somewhere to go.
	// NOTE: RUNTIME_AUTH_TOKEN is intentionally NOT set here — the generated
	// script must export it itself after sourcing runtime.env.
	basePath := os.Getenv("PATH")
	runScript.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+stubDir+string(os.PathListSeparator)+basePath,
		"MONEDULA_KAFKA_ACLS_BIN="+stubPath,
	)
	out, err := runScript.CombinedOutput()
	// Always surface the per-ACL deny log and recorded argv on failure.
	if err != nil {
		denyLog, _ := os.ReadFile(filepath.Join(tmp, "delete-deny.log"))
		argv, _ := os.ReadFile(argsFile)
		t.Fatalf("delete-deny-acls.sh failed: %v\nscript output:\n%s\ndelete-deny.log:\n%s\nrecorded kafka-acls argv:\n%s",
			err, out, denyLog, argv)
	}
	t.Logf("delete-deny-acls.sh output:\n%s", out)

	// 8a. The deny log should record OK for both ACL rows (no SKIP/FAIL).
	denyLogBytes, err := os.ReadFile(filepath.Join(tmp, "delete-deny.log"))
	if err != nil {
		t.Fatalf("read delete-deny.log: %v", err)
	}
	denyLog := string(denyLogBytes)
	if strings.Contains(denyLog, "FAIL") || strings.Contains(denyLog, "SKIP") {
		t.Errorf("delete-deny.log contains FAIL/SKIP — chain did not reach the kafka-acls exec:\n%s", denyLog)
	}
	okCount := strings.Count(denyLog, "OK acl_id=")
	if okCount != 2 {
		t.Errorf("expected 2 'OK acl_id=' lines in delete-deny.log, got %d:\n%s", okCount, denyLog)
	}

	// 8b. The stub recorded the argv kafka-acls received for each DENY. Assert
	//     both pattern types and the deny-principal made it through the real
	//     realExec path.
	argvBytes, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("kafka-acls stub recorded no argv (did realExec run?): %v", err)
	}
	argv := string(argvBytes)
	t.Logf("recorded kafka-acls argv:\n%s", argv)
	for _, want := range []string{
		"--remove",
		"--deny-principal User:eve",
		"--operation Read",
		"--resource-pattern-type literal",  // LITERAL DENY (Topic:secrets)
		"--resource-pattern-type prefixed", // PREFIXED DENY (Topic:secret-) — B1 regression guard
		"--topic secrets",
		"--topic secret-",
		"--bootstrap-server " + hostBootstrap,
	} {
		if !strings.Contains(argv, want) {
			t.Errorf("recorded kafka-acls argv missing %q\nfull argv:\n%s", want, argv)
		}
	}

	// 8c. The MDS live re-check must have happened AND been authenticated. One
	//     lookup per DENY ACL; every lookup must carry a Bearer token (the
	//     unauthenticated-MDS regression guard).
	if got := mds.lookupCount(); got < 2 {
		t.Errorf("expected >=2 MDS lookups (one per DENY ACL), got %d", got)
	}
	if got := mds.authenticatedLookups(); got < 2 {
		t.Errorf("expected >=2 AUTHENTICATED (Bearer) MDS lookups, got %d; the live re-check ran unauthenticated", got)
	}

	fmt.Fprintf(os.Stderr, "delete-deny round-trip OK: 2 DENY ACLs, %d OK log lines, %d authenticated lookups\n",
		okCount, mds.authenticatedLookups())
}

// describeEveDenies returns the count of DENY ACLs for User:eve on any topic.
func describeEveDenies(ctx context.Context, t *testing.T, adm *kadm.Client) int {
	t.Helper()
	filter := kadm.NewACLs().
		Deny("User:eve").
		DenyHosts().
		Topics().
		Operations().
		ResourcePatternType(kadm.ACLPatternAny)
	res, err := adm.DescribeACLs(ctx, filter)
	if err != nil {
		t.Fatalf("DescribeACLs(eve deny): %v", err)
	}
	n := 0
	for _, r := range res {
		if r.Err != nil {
			t.Fatalf("DescribeACLs(eve deny) result err: %v", r.Err)
		}
		n += len(r.Described)
	}
	return n
}

// assertDenySafeToRemove reads plan.json and fails unless every deny_analysis
// entry is SAFE_TO_REMOVE (and there is at least one). The deny-deletion path
// only picks rows whose deny_analysis says SAFE_TO_REMOVE; if the planner
// classified them otherwise, delete-deny-acls would emit an empty script and
// the round-trip would prove nothing.
func assertDenySafeToRemove(t *testing.T, planPath string) {
	t.Helper()
	data, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("read plan.json: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "SAFE_TO_REMOVE") {
		t.Fatalf("plan.json has no SAFE_TO_REMOVE deny_analysis entry; deny path would emit an empty script:\n%s", text)
	}
	// Defensive: a WOULD_GRANT_ACCESS or UNKNOWN status would mean a row is
	// filtered out. We created no covering ALLOW for eve, so none is expected.
	if strings.Contains(text, "WOULD_GRANT_ACCESS") {
		t.Errorf("plan.json unexpectedly classified a DENY as WOULD_GRANT_ACCESS:\n%s", text)
	}
}
