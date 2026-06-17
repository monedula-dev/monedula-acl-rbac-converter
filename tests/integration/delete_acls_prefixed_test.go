// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build integration

package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
)

// TestRealBroker_DeleteACLs_PrefixedPattern proves that a generated
// `kafka-acls --remove ... --resource-pattern-type prefixed` actually removes a
// PREFIXED ALLOW ACL from a REAL cp-kafka broker. This is the cheapest honest
// proof that real kafka-acls accepts (and acts on) the prefixed pattern flag —
// the same flag the DENY path depends on (bug B1 dropped it). The deny
// round-trip (delete_deny_acls_roundtrip_test.go) deliberately stops at the
// kafka-acls argv; this test closes the loop on the broker mutation itself for
// the allow/delete-acls path, where the script runs in-container and needs only
// kafka-acls (no monedula binary, no MDS route).
//
// Shape mirrors TestRealBroker_DeleteACLs_RoundTrip but with a single PREFIXED
// ALLOW ACL and an in-container script execution. We do not run rollback here;
// the point is solely to prove the prefixed --remove lands.
func TestRealBroker_DeleteACLs_PrefixedPattern(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	c, brokers := startCpKafkaContainer(ctx, t)
	defer func() {
		if err := c.Terminate(ctx); err != nil {
			t.Logf("container terminate: %v", err)
		}
	}()
	t.Logf("cp-kafka brokers (external): %v", brokers)

	// Internal BROKER listener for in-container kafka-acls — same derivation as
	// the delete-acls round-trip.
	inspect, err := c.Inspect(ctx)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	internalBootstrap := inspect.Config.Hostname + ":9092"
	t.Logf("internal bootstrap address: %s", internalBootstrap)

	// Create one PREFIXED ALLOW ACL: User:carol Read on Topic:events- PREFIXED.
	cl, err := kgo.NewClient(kgo.SeedBrokers(brokers...))
	if err != nil {
		t.Fatalf("kgo client: %v", err)
	}
	adm := kadm.NewClient(cl)
	defer cl.Close()

	prefixedAllow := kadm.NewACLs().
		Allow("User:carol").
		AllowHosts("*").
		Topics("events-").
		ResourcePatternType(kadm.ACLPatternPrefixed).
		Operations(kadm.OpRead, kadm.OpDescribe)
	res, err := adm.CreateACLs(ctx, prefixedAllow)
	if err != nil {
		t.Fatalf("CreateACLs (prefixed allow): %v", err)
	}
	for _, r := range res {
		if r.Err != nil {
			t.Skipf("CreateACLs returned %v — broker may not have ACL security enabled; skipping", r.Err)
		}
	}

	if got := describeCarolPrefixed(ctx, t, adm); got == 0 {
		t.Fatalf("pre-delete: expected PREFIXED ACLs for carol, got 0")
	}

	mds := newContractMDS()
	defer mds.srv.Close()

	tmp := t.TempDir()
	aclsPath := filepath.Join(tmp, "acls.json")
	scopesPath := filepath.Join(tmp, "scopes.yaml")
	planPath := filepath.Join(tmp, "plan.json")
	verifyPath := filepath.Join(tmp, "verify.json")
	tokenPath := filepath.Join(tmp, "token")
	deleteScript := filepath.Join(tmp, "delete-acls.sh")

	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("fake-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	hostBootstrap := strings.Join(brokers, ",")

	if exit := cli.Execute([]string{
		"extract", "--from", "live",
		"--bootstrap-server", hostBootstrap,
		"--out", aclsPath,
	}); exit != 0 {
		t.Fatalf("extract exit %d", exit)
	}

	// The PREFIXED ALLOW for carol must round-trip through extract; assert it
	// landed with its pattern type so the deletion script targets it correctly.
	aclsData, err := os.ReadFile(aclsPath)
	if err != nil {
		t.Fatalf("read acls.json: %v", err)
	}
	if !strings.Contains(string(aclsData), "PREFIXED") {
		t.Fatalf("acls.json did not capture the PREFIXED pattern type:\n%s", aclsData)
	}

	if exit := cli.Execute([]string{
		"plan",
		"--acls", aclsPath,
		"--scopes", scopesPath,
		"--out", planPath,
	}); exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}

	if exit := cli.Execute([]string{
		"apply",
		"--plan", planPath,
		"--mds-url", mds.srv.URL,
		"--mds-token-file", tokenPath,
		"--confirm",
	}); exit != 0 {
		t.Fatalf("apply exit %d; MDS requests so far: %v", exit, mds.requests)
	}

	if exit := cli.Execute([]string{
		"verify",
		"--plan", planPath,
		"--mds-url", mds.srv.URL,
		"--mds-token-file", tokenPath,
	}); exit != 0 {
		t.Fatalf("verify exit %d", exit)
	}

	if exit := cli.Execute([]string{
		"delete-acls",
		"--plan", planPath,
		"--verify", verifyPath,
		"--bootstrap-server", hostBootstrap,
		"--principal", "User:carol",
		"--confirm", "--i-understand-this-is-destructive",
	}); exit != 0 {
		t.Fatalf("delete-acls exit %d", exit)
	}

	// Read & rewrite the script for in-container execution, then assert it
	// contains the prefixed pattern flag before running it.
	delScriptBytes, err := os.ReadFile(deleteScript)
	if err != nil {
		t.Fatalf("read delete-acls.sh: %v", err)
	}
	// The emitter shell-quotes every kafka-acls token (flags included, a
	// deliberate injection hardening), so the pattern type appears as
	// '--resource-pattern-type' 'prefixed'.
	if !strings.Contains(string(delScriptBytes), "'--resource-pattern-type' 'prefixed'") {
		t.Fatalf("delete-acls.sh missing `'--resource-pattern-type' 'prefixed'`:\n%s", delScriptBytes)
	}
	delScriptRewritten := rewriteScriptForContainer(string(delScriptBytes), hostBootstrap, internalBootstrap)
	if !strings.Contains(delScriptRewritten, internalBootstrap) {
		t.Fatalf("rewrite missed bootstrap substitution; script:\n%s", delScriptRewritten)
	}
	if !strings.Contains(delScriptRewritten, "LOG=/tmp/delete.log") {
		t.Fatalf("rewrite missed LOG substitution; script:\n%s", delScriptRewritten)
	}

	if err := c.CopyToContainer(ctx, []byte(delScriptRewritten), "/tmp/delete-acls.sh", 0o755); err != nil {
		t.Fatalf("CopyToContainer delete-acls.sh: %v", err)
	}

	// The script's plan.sha256 guard is fail-closed and would refuse to run
	// because plan.json lives in the host run-dir, not in the container. This
	// mirrors the documented "copy the script into a broker container" workflow:
	// set MONEDULA_SKIP_PLAN_HASH_CHECK=1 to skip the integrity check. (The
	// guard's pass/refuse/override behaviour is proven directly in
	// pkg/aclrbac/delete/common: TestHeader_RuntimeGuard_Executes.)
	delOut, delCode := execInContainer(ctx, t, c, []string{"sh", "-c", "MONEDULA_SKIP_PLAN_HASH_CHECK=1 bash /tmp/delete-acls.sh"})
	if delCode != 0 {
		logOut, _ := execInContainer(ctx, t, c, []string{"sh", "-c", "cat /tmp/delete.log 2>/dev/null || echo '(no log)'"})
		t.Fatalf("delete-acls.sh exit=%d\nstdout+stderr:\n%s\n/tmp/delete.log:\n%s", delCode, delOut, logOut)
	}

	// The real `kafka-acls --remove ... --resource-pattern-type prefixed` must
	// have removed carol's PREFIXED ACLs from the live broker.
	if got := describeCarolPrefixed(ctx, t, adm); got != 0 {
		t.Errorf("post-delete: expected 0 PREFIXED ACLs for carol, got %d", got)
	}
}

// describeCarolPrefixed counts PREFIXED ACLs for User:carol on any topic.
func describeCarolPrefixed(ctx context.Context, t *testing.T, adm *kadm.Client) int {
	t.Helper()
	filter := kadm.NewACLs().
		Allow("User:carol").
		AllowHosts().
		Topics().
		Operations().
		ResourcePatternType(kadm.ACLPatternPrefixed)
	res, err := adm.DescribeACLs(ctx, filter)
	if err != nil {
		t.Fatalf("DescribeACLs(carol prefixed): %v", err)
	}
	n := 0
	for _, r := range res {
		if r.Err != nil {
			t.Fatalf("DescribeACLs(carol prefixed) result err: %v", r.Err)
		}
		n += len(r.Described)
	}
	return n
}
