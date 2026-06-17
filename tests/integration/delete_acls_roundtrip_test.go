// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tcgo "github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
)

// startCpKafkaContainer brings up confluentinc/cp-kafka:7.9.7 in
// KRaft mode with StandardAuthorizer and ANONYMOUS-as-superuser, the
// same authorization shape as startCpKafka but also returns the
// underlying *kafka.KafkaContainer so callers can Exec / CopyToContainer.
func startCpKafkaContainer(ctx context.Context, t *testing.T) (*kafka.KafkaContainer, []string) {
	t.Helper()
	c, err := kafka.Run(ctx,
		"confluentinc/cp-kafka:7.9.7",
		kafka.WithClusterID("integration-cluster"),
		tcgo.WithEnv(map[string]string{
			"KAFKA_AUTHORIZER_CLASS_NAME":          "org.apache.kafka.metadata.authorizer.StandardAuthorizer",
			"KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND": "true",
			"KAFKA_SUPER_USERS":                    "User:ANONYMOUS",
		}),
	)
	if err != nil {
		t.Skipf("Docker / cp-kafka unavailable: %v", err)
	}
	addrs, err := c.Brokers(ctx)
	if err != nil {
		_ = c.Terminate(ctx)
		t.Fatalf("brokers: %v", err)
	}
	return c, addrs
}

// execInContainer runs cmd in container and returns combined stdout+stderr
// plus the exit code.
func execInContainer(ctx context.Context, t *testing.T, c *kafka.KafkaContainer, cmd []string) (string, int) {
	t.Helper()
	code, reader, err := c.Exec(ctx, cmd, tcexec.Multiplexed())
	if err != nil {
		t.Fatalf("exec %v: %v", cmd, err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read exec output for %v: %v", cmd, err)
	}
	return string(out), code
}

// rewriteScriptForContainer adjusts the generated script's host-bound
// paths and bootstrap address so it can run inside the cp-kafka
// container. Substitutions:
//
//   - The host's mapped <host>:<port> bootstrap (used in the
//     '# bootstrap-server:' comment and every 'kafka-acls
//     --bootstrap-server …' invocation) becomes the container's
//     internal BROKER listener at <internalHost>:9092.
//   - LOG='/host/abs/run-dir/delete.log' becomes LOG=/tmp/delete.log
//     so '>> $LOG' redirects work inside the container.
//
// The '# Run directory (absolute): C:\...' comment line is
// informational; we leave it alone.
func rewriteScriptForContainer(script, hostBootstrap, internalBootstrap string) string {
	out := strings.ReplaceAll(script, hostBootstrap, internalBootstrap)
	// LOG='/abs/path/delete.log' -> LOG=/tmp/delete.log. We replace
	// the entire single-quoted token to avoid matching path
	// fragments embedded elsewhere.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "LOG=") {
			out = strings.Replace(out, line, "LOG=/tmp/delete.log", 1)
			break
		}
	}
	return out
}

// describeAliceAndBob returns flat DescribedACL slices for alice's and
// bob's deny+allow surface, regardless of operation. We DescribeACLs
// with a broad filter (per-principal, any topic, any op) so the
// returned set tells us whether each principal's ACLs are present.
func describeAliceAndBob(ctx context.Context, t *testing.T, adm *kadm.Client) (alice, bob []kadm.DescribedACL) {
	t.Helper()
	for _, who := range []string{"User:alice", "User:bob"} {
		filter := kadm.NewACLs().
			Allow(who).
			AllowHosts().
			Topics().
			Operations().
			ResourcePatternType(kadm.ACLPatternAny)
		res, err := adm.DescribeACLs(ctx, filter)
		if err != nil {
			t.Fatalf("DescribeACLs(%s): %v", who, err)
		}
		var flat []kadm.DescribedACL
		for _, r := range res {
			if r.Err != nil {
				t.Fatalf("DescribeACLs(%s) result err: %v", who, r.Err)
			}
			flat = append(flat, r.Described...)
		}
		if who == "User:alice" {
			alice = flat
		} else {
			bob = flat
		}
	}
	return alice, bob
}

// TestRealBroker_DeleteACLs_RoundTrip exercises the full
// extract → plan → apply → delete-acls (script mode) pipeline against a
// real cp-kafka container, then *executes* the generated delete-acls.sh
// and rollback.sh INSIDE the container. The point is to close the gap
// between "script content is golden-tested" and "script actually does
// what it says when run against a real broker": after delete-acls.sh
// runs, DescribeACLs must show alice's & bob's ACLs gone; after
// rollback.sh runs, DescribeACLs must show them back.
//
// The host-mapped bootstrap address and LOG path are rewritten before
// copy-in to use the container's internal BROKER listener and a
// writable /tmp/ location respectively. See rewriteScriptForContainer
// for details.
func TestRealBroker_DeleteACLs_RoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	c, brokers := startCpKafkaContainer(ctx, t)
	defer func() {
		if err := c.Terminate(ctx); err != nil {
			t.Logf("container terminate: %v", err)
		}
	}()
	t.Logf("cp-kafka brokers (external): %v", brokers)

	// Probe: confirm kafka-acls is on PATH inside the container and
	// dump KAFKA_LISTENERS so a future diff makes the assumption
	// explicit when cp-kafka 8.x lands. The cp-kafka image lacks a
	// 'which' binary in $PATH; use 'command -v' via sh, which is a
	// POSIX builtin and works on every cp-kafka tag we ship against.
	if out, code := execInContainer(ctx, t, c, []string{"sh", "-c", "command -v kafka-acls"}); code != 0 {
		t.Fatalf("`command -v kafka-acls` exit=%d output=%q", code, out)
	} else {
		t.Logf("kafka-acls path: %s", strings.TrimSpace(out))
	}
	if out, code := execInContainer(ctx, t, c, []string{"sh", "-c", "echo $KAFKA_LISTENERS; echo $KAFKA_ADVERTISED_LISTENERS; hostname"}); code != 0 {
		t.Fatalf("listeners probe exit=%d output=%q", code, out)
	} else {
		t.Logf("listener probe:\n%s", out)
	}

	// The cp-kafka container exposes:
	//   PLAINTEXT://0.0.0.0:9093  (advertised as external host:mappedPort)
	//   BROKER://0.0.0.0:9092     (advertised as <containerHostname>:9092)
	// From inside the container the BROKER listener is reachable
	// because <containerHostname> resolves to the container itself.
	inspect, err := c.Inspect(ctx)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	internalBootstrap := inspect.Config.Hostname + ":9092"
	t.Logf("internal bootstrap address for in-container kafka-acls: %s", internalBootstrap)

	// Create the source ACLs via kadm (against the external listener).
	cl, err := kgo.NewClient(kgo.SeedBrokers(brokers...))
	if err != nil {
		t.Fatalf("kgo client: %v", err)
	}
	adm := kadm.NewClient(cl)
	defer cl.Close()

	aliceACLs := kadm.NewACLs().
		Allow("User:alice").
		AllowHosts("*").
		Topics("orders").
		ResourcePatternType(kadm.ACLPatternLiteral).
		Operations(kadm.OpRead, kadm.OpDescribe)
	bobACLs := kadm.NewACLs().
		Allow("User:bob").
		AllowHosts("*").
		Topics("payments").
		ResourcePatternType(kadm.ACLPatternLiteral).
		Operations(kadm.OpWrite, kadm.OpDescribe)

	for _, b := range []*kadm.ACLBuilder{aliceACLs, bobACLs} {
		res, err := adm.CreateACLs(ctx, b)
		if err != nil {
			t.Fatalf("CreateACLs: %v", err)
		}
		for _, r := range res {
			if r.Err != nil {
				t.Skipf("CreateACLs returned %v — broker may not have ACL security enabled; skipping", r.Err)
			}
		}
	}

	// Sanity: both principals have 2 ACLs each before deletion.
	alice0, bob0 := describeAliceAndBob(ctx, t, adm)
	if len(alice0) != 2 {
		t.Fatalf("pre-delete: expected 2 ACLs for alice, got %d: %v", len(alice0), alice0)
	}
	if len(bob0) != 2 {
		t.Fatalf("pre-delete: expected 2 ACLs for bob, got %d: %v", len(bob0), bob0)
	}

	// Stand up the fake MDS. Use the two-principal variant so verify
	// can produce EFFECTIVE_OK for BOTH alice and bob's bindings.
	mds := newContractMDS()
	defer mds.srv.Close()

	tmp := t.TempDir()
	aclsPath := filepath.Join(tmp, "acls.json")
	scopesPath := filepath.Join(tmp, "scopes.yaml")
	planPath := filepath.Join(tmp, "plan.json")
	verifyPath := filepath.Join(tmp, "verify.json")
	tokenPath := filepath.Join(tmp, "token")
	deleteScript := filepath.Join(tmp, "delete-acls.sh")
	rollbackScript := filepath.Join(tmp, "rollback.sh")

	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("fake-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	hostBootstrap := strings.Join(brokers, ",")

	// extract --from live (against real cp-kafka).
	if exit := cli.Execute([]string{
		"extract", "--from", "live",
		"--bootstrap-server", hostBootstrap,
		"--out", aclsPath,
	}); exit != 0 {
		t.Fatalf("extract exit %d", exit)
	}

	// plan.
	if exit := cli.Execute([]string{
		"plan",
		"--acls", aclsPath,
		"--scopes", scopesPath,
		"--out", planPath,
	}); exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}

	// apply --confirm (against httptest MDS).
	if exit := cli.Execute([]string{
		"apply",
		"--plan", planPath,
		"--mds-url", mds.srv.URL,
		"--mds-token-file", tokenPath,
		"--confirm",
	}); exit != 0 {
		t.Fatalf("apply exit %d; MDS requests so far: %v", exit, mds.requests)
	}

	// verify --mode effective (the default, recommended path). Until the
	// BindingID fix in pkg/aclrbac/verify/effective.go landed, effective
	// mode produced Results with only SourceACLID populated and
	// delete-acls's eligibility map (keyed on BindingID) silently
	// missed everything. This test locks in the round trip end-to-end.
	if exit := cli.Execute([]string{
		"verify",
		"--plan", planPath,
		"--mds-url", mds.srv.URL,
		"--mds-token-file", tokenPath,
	}); exit != 0 {
		t.Fatalf("verify exit %d", exit)
	}

	// delete-acls in script-emission mode, scoped to BOTH principals.
	if exit := cli.Execute([]string{
		"delete-acls",
		"--plan", planPath,
		"--verify", verifyPath,
		"--bootstrap-server", hostBootstrap,
		"--principal", "User:alice",
		"--principal", "User:bob",
		"--confirm", "--i-understand-this-is-destructive",
	}); exit != 0 {
		t.Fatalf("delete-acls exit %d", exit)
	}

	// Read & rewrite delete-acls.sh, then copy into the container.
	delScriptBytes, err := os.ReadFile(deleteScript)
	if err != nil {
		t.Fatalf("read delete-acls.sh: %v", err)
	}
	delScriptRewritten := rewriteScriptForContainer(string(delScriptBytes), hostBootstrap, internalBootstrap)
	if !strings.Contains(delScriptRewritten, internalBootstrap) {
		t.Fatalf("rewrite missed bootstrap substitution; script:\n%s", delScriptRewritten)
	}
	if !strings.Contains(delScriptRewritten, "LOG=/tmp/delete.log") {
		t.Fatalf("rewrite missed LOG substitution; script:\n%s", delScriptRewritten)
	}
	t.Logf("rewritten delete-acls.sh (first 400 chars):\n%.400s", delScriptRewritten)

	// 0o755 (world-read+exec) rather than the script's on-disk
	// 0o700: testcontainers copies in as root, but the cp-kafka
	// image's entrypoint runs as 'appuser', so a 0o700 root-owned
	// file isn't even readable to the runtime user.
	if err := c.CopyToContainer(ctx, []byte(delScriptRewritten), "/tmp/delete-acls.sh", 0o755); err != nil {
		t.Fatalf("CopyToContainer delete-acls.sh: %v", err)
	}

	// Execute delete-acls.sh inside the container. The script's plan.sha256
	// guard is fail-closed and would refuse to run because plan.json lives in
	// the host run-dir, not in the container (the documented "copy the script
	// into a broker container" case). Set MONEDULA_SKIP_PLAN_HASH_CHECK=1 to
	// skip the integrity check; its pass/refuse/override behaviour is proven in
	// pkg/aclrbac/delete/common: TestHeader_RuntimeGuard_Executes.
	delOut, delCode := execInContainer(ctx, t, c, []string{"sh", "-c", "MONEDULA_SKIP_PLAN_HASH_CHECK=1 bash /tmp/delete-acls.sh"})
	if delCode != 0 {
		// Dump the LOG too if it exists; failure mode is "kafka-acls
		// itself returned non-zero", in which case the script logged
		// the failed acl_id.
		logOut, _ := execInContainer(ctx, t, c, []string{"sh", "-c", "cat /tmp/delete.log 2>/dev/null || echo '(no log)'"})
		t.Fatalf("delete-acls.sh exit=%d\nstdout+stderr:\n%s\n/tmp/delete.log:\n%s", delCode, delOut, logOut)
	}

	// Verify ACLs are gone.
	alice1, bob1 := describeAliceAndBob(ctx, t, adm)
	if len(alice1) != 0 {
		t.Errorf("post-delete: expected 0 ACLs for alice, got %d: %+v", len(alice1), alice1)
	}
	if len(bob1) != 0 {
		t.Errorf("post-delete: expected 0 ACLs for bob, got %d: %+v", len(bob1), bob1)
	}

	// Read & rewrite rollback.sh, then copy into the container.
	rollScriptBytes, err := os.ReadFile(rollbackScript)
	if err != nil {
		t.Fatalf("read rollback.sh: %v", err)
	}
	// rollback.sh has no LOG line, but the bootstrap substitution
	// is still needed. rewriteScriptForContainer's LOG branch is a
	// no-op if there's no LOG= line, so it's safe to call.
	rollScriptRewritten := rewriteScriptForContainer(string(rollScriptBytes), hostBootstrap, internalBootstrap)
	if !strings.Contains(rollScriptRewritten, internalBootstrap) {
		t.Fatalf("rewrite missed bootstrap substitution in rollback.sh; script:\n%s", rollScriptRewritten)
	}
	t.Logf("rewritten rollback.sh (first 400 chars):\n%.400s", rollScriptRewritten)

	if err := c.CopyToContainer(ctx, []byte(rollScriptRewritten), "/tmp/rollback.sh", 0o755); err != nil {
		t.Fatalf("CopyToContainer rollback.sh: %v", err)
	}

	// Same fail-closed plan.sha256 guard as delete-acls.sh — skip it in-container
	// (plan.json isn't here); see the note on the delete-acls.sh exec above.
	rollOut, rollCode := execInContainer(ctx, t, c, []string{"sh", "-c", "MONEDULA_SKIP_PLAN_HASH_CHECK=1 bash /tmp/rollback.sh"})
	if rollCode != 0 {
		t.Fatalf("rollback.sh exit=%d\nstdout+stderr:\n%s", rollCode, rollOut)
	}

	// Verify ACLs are back. We don't require exact equality with
	// alice0/bob0 (host/permission canonicalisation could differ
	// trivially), but we DO require the same count of allow ACLs
	// per principal across the same (resource, operation) pairs.
	alice2, bob2 := describeAliceAndBob(ctx, t, adm)
	if len(alice2) != 2 {
		t.Errorf("post-rollback: expected 2 ACLs for alice, got %d: %+v", len(alice2), alice2)
	}
	if len(bob2) != 2 {
		t.Errorf("post-rollback: expected 2 ACLs for bob, got %d: %+v", len(bob2), bob2)
	}

	// Spot-check: the operation set per principal should match the
	// original (Read+Describe for alice, Write+Describe for bob).
	checkOps := func(name string, got []kadm.DescribedACL, wantOps map[string]bool) {
		gotOps := map[string]bool{}
		for _, a := range got {
			gotOps[a.Operation.String()] = true
		}
		for op := range wantOps {
			if !gotOps[op] {
				t.Errorf("%s post-rollback missing operation %q (got %v)", name, op, gotOps)
			}
		}
	}
	checkOps("alice", alice2, map[string]bool{"READ": true, "DESCRIBE": true})
	checkOps("bob", bob2, map[string]bool{"WRITE": true, "DESCRIBE": true})

	fmt.Fprintf(os.Stderr, "round-trip OK: %d alice ACLs before, %d after delete, %d after rollback\n",
		len(alice0), len(alice1), len(alice2))
}
