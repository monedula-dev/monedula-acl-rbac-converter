// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build e2e

// Package e2e_test exercises the monedula-acl-rbac binary end-to-end against a
// REAL Confluent stack: a cp-server broker (ACL source) and its co-located
// RBAC/MDS (apply + verify target), both stood up by internal/mdstest. There
// are no in-process fakes here — the full extract → plan → apply → verify path
// runs over the wire, on a deliberately complex, real-life ACL set.
//
// Gated behind `-tags e2e` and Docker: the stack t.Skip()s when Docker is
// unavailable, and the ACL-creation step t.Skip()s if the broker rejects ACL
// management (so a misconfigured broker doesn't masquerade as a tool bug).
package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tcgo "github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"

	"github.com/monedula-dev/monedula-acl-rbac-converter/internal/mdstest"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// scenario is one real-life Kafka ACL and the RBAC binding(s) it should convert
// to. The same struct drives both halves: the source ACL created on the broker
// and the expected binding(s) asserted in MDS. len(wantRoles) == 0 means the
// scenario yields no binding (a DENY, which converts to a rejected entry). A
// scenario can map to more than one role: a principal holding Read AND Write on
// one resource needs both DeveloperRead and DeveloperWrite (RBAC is additive).
type scenario struct {
	principal string
	resType   types.ResourceType // Topic | Group
	name      string
	prefixed  bool
	ops       []kadm.ACLOperation
	deny      bool
	wantRoles []string
}

var (
	readDescribe      = []kadm.ACLOperation{kadm.OpRead, kadm.OpDescribe}
	writeDescribe     = []kadm.ACLOperation{kadm.OpWrite, kadm.OpDescribe}
	readWriteDescribe = []kadm.ACLOperation{kadm.OpRead, kadm.OpWrite, kadm.OpDescribe}
	allOps            = []kadm.ACLOperation{kadm.OpAll}
)

// complexScenarios is a realistic microservices-platform ACL set: a consumer
// that reads a topic AND commits to its consumer group (two bindings for one
// principal), a producer, a prefixed analytics reader, a second consumer, a
// read-write relay that both consumes and produces one topic (Read+Write → two
// roles), and a DENY that must be rejected rather than converted. It spans
// Topic + Group resources, Read/Write/Describe operations, LITERAL + PREFIXED
// patterns, single- and multi-role groups, and the ALLOW/DENY split — enough
// shape to shake out wire-contract drift end to end while staying fully
// effective-verifiable (every ALLOW operation maps to a role whose catalogue
// genuinely grants it).
var complexScenarios = []scenario{
	{principal: "User:svc-orders-consumer", resType: types.ResourceTopic, name: "orders", ops: readDescribe, wantRoles: []string{"DeveloperRead"}},
	{principal: "User:svc-orders-consumer", resType: types.ResourceGroup, name: "orders-consumers", ops: readDescribe, wantRoles: []string{"DeveloperRead"}},
	{principal: "User:svc-payments-producer", resType: types.ResourceTopic, name: "payments", ops: writeDescribe, wantRoles: []string{"DeveloperWrite"}},
	{principal: "User:svc-analytics", resType: types.ResourceTopic, name: "events.", prefixed: true, ops: readDescribe, wantRoles: []string{"DeveloperRead"}},
	{principal: "User:svc-fulfillment", resType: types.ResourceTopic, name: "shipments", ops: readDescribe, wantRoles: []string{"DeveloperRead"}},
	// Read AND Write on one topic: a single Developer* role can't grant both,
	// so the planner emits two bindings (DeveloperRead + DeveloperWrite).
	{principal: "User:svc-orders-relay", resType: types.ResourceTopic, name: "orders", ops: readWriteDescribe, wantRoles: []string{"DeveloperRead", "DeveloperWrite"}},
	// A DENY: must become a rejected entry, never a binding.
	{principal: "User:legacy-importer", resType: types.ResourceTopic, name: "pii-events", ops: []kadm.ACLOperation{kadm.OpRead}, deny: true},
}

// allOpScenarios exercises the `All`-operation -> ResourceOwner role mapping,
// which the effective-verifiable complexScenarios deliberately avoid (an `All`
// source op never exact-matches a role's concrete allowedOperations, so
// effective verify can't confirm it). These are checked with bindings-exist
// only, across the two resource types ResourceOwner scopes to:
//   - All on a Topic -> ResourceOwner (Topic pattern)
//   - All on a Group -> ResourceOwner (Group pattern)
//
// They run as a separate pipeline against the same live stack so the concrete
// set stays fully effective-verifiable.
//
// The fourth default `All` rule — All on the Cluster -> SystemAdmin — is NOT
// exercised live: SystemAdmin is a cluster-admin role that this cp-server trial
// does not offer at the kafka-cluster scope (apply gets MDS 400 "No role
// SystemAdmin at scope ... kafka-cluster"). Cluster-admin roles are granted at a
// higher registry scope in real Confluent deployments; that scope catalogue is
// out of scope for this converter's e2e. The mapping itself is unit-tested in
// the planner.
var allOpScenarios = []scenario{
	{principal: "User:svc-orders-owner", resType: types.ResourceTopic, name: "orders", ops: allOps, wantRoles: []string{"ResourceOwner"}},
	{principal: "User:svc-group-owner", resType: types.ResourceGroup, name: "order-events", ops: allOps, wantRoles: []string{"ResourceOwner"}},
}

// countAllowBindings counts the role bindings the ALLOW scenarios in a set must
// produce and MDS must hold. A scenario can map to more than one role, so this
// sums wantRoles across scenarios rather than counting scenario rows.
func countAllowBindings(scenarios []scenario) int {
	n := 0
	for _, s := range scenarios {
		n += len(s.wantRoles)
	}
	return n
}

// principalsOf returns the distinct principals in a scenario set, in first-seen
// order — used to scope `extract --principal-filter` to one pipeline's set.
func principalsOf(scenarios []scenario) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range scenarios {
		if !seen[s.principal] {
			seen[s.principal] = true
			out = append(out, s.principal)
		}
	}
	return out
}

// allowPrincipalsOf returns the distinct principals of the ALLOW scenarios only
// (DENYs convert to rejected entries, so they hold no binding and nothing to
// delete).
func allowPrincipalsOf(scenarios []scenario) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range scenarios {
		if len(s.wantRoles) == 0 || seen[s.principal] {
			continue
		}
		seen[s.principal] = true
		out = append(out, s.principal)
	}
	return out
}

func patternType(s scenario) types.PatternType {
	if s.prefixed {
		return types.PatternPrefixed
	}
	return types.PatternLiteral
}

// opName maps the kadm operations this test uses to their canonical acls.json
// (types.Operation) spelling, so the extract assertion can check the exact rows
// that landed rather than substrings.
func opName(op kadm.ACLOperation) types.Operation {
	switch op {
	case kadm.OpRead:
		return types.OpRead
	case kadm.OpWrite:
		return types.OpWrite
	case kadm.OpDescribe:
		return types.OpDescribe
	case kadm.OpAll:
		return types.OpAll
	default:
		return types.Operation(op.String())
	}
}

// TestE2E_ComplexPipeline_LiveMDS runs extract → plan → apply → verify against
// a real cp-server broker + MDS, per CP version, on the complex ACL set.
func TestE2E_ComplexPipeline_LiveMDS(t *testing.T) {
	for _, spec := range mdstest.CPSpecs {
		t.Run(spec.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
			defer cancel()

			stack, terminate := mdstest.StartMDSStack(ctx, t, spec)
			defer terminate()
			t.Logf("%s up: MDS=%s broker=%v cluster=%s", spec.Name, stack.URL, stack.Brokers, stack.ClusterID)

			// Create both scenario sets up front; each pipeline then extracts its
			// own principals via --principal-filter so the concrete set stays
			// fully effective-verifiable and the All-op set is checked separately.
			allScenarios := append(append([]scenario{}, complexScenarios...), allOpScenarios...)
			createScenarioACLs(ctx, t, stack.Brokers, stack.Kafka, allScenarios)

			mdsArgs := []string{"--mds-url", stack.URL, "--mds-user", "mds", "--mds-password-file", stack.PWFile}

			// Pipeline A: the concrete-op set — extract → plan → apply → verify
			// (bindings-exist + effective) → delete the source ACLs and confirm
			// they're gone from the real broker.
			runConcretePipeline(ctx, t, stack, mdsArgs)

			// Pipeline B: the All-op role mappings (ResourceOwner / SystemAdmin),
			// verified by bindings-exist only.
			runAllOpPipeline(ctx, t, stack, mdsArgs)
		})
	}
}

// runConcretePipeline drives the effective-verifiable complexScenarios through
// extract → plan → apply → verify (bindings-exist + effective) against the live
// stack, scoping extract to those principals.
func runConcretePipeline(ctx context.Context, t *testing.T, stack mdstest.Stack, mdsArgs []string) {
	t.Helper()
	dir := t.TempDir()
	aclsPath := filepath.Join(dir, "acls.json")
	scopesPath := filepath.Join(dir, "scopes.yaml")
	planPath := filepath.Join(dir, "plan.json")
	reportPath := filepath.Join(dir, "report.txt")
	verifyPath := filepath.Join(dir, "verify.json")
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: "+stack.ClusterID+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := countAllowBindings(complexScenarios)

	// 1. extract --from live, scoped to the concrete principals (real broker
	// over SASL_PLAINTEXT; the command-config carries the kafka-superuser PLAIN
	// credentials). Assert each created ACL round-tripped with the exact shape.
	extractArgs := append([]string{
		"extract", "--from", "live",
		"--bootstrap-server", strings.Join(stack.Brokers, ","),
		"--command-config", stack.CommandConfig,
		"--out", aclsPath,
	}, principalFilterArgs(principalsOf(complexScenarios))...)
	if exit := cli.Execute(extractArgs); exit != 0 {
		t.Fatalf("extract exit %d", exit)
	}
	assertExtractedACLs(t, aclsPath, complexScenarios)

	// 2. plan (--allow-rejected: the DENY converts to a rejected entry).
	if exit := cli.Execute([]string{
		"plan", "--acls", aclsPath, "--scopes", scopesPath,
		"--out", planPath, "--allow-rejected",
	}); exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}
	if got := planBindingCount(t, planPath); got != want {
		t.Fatalf("plan produced %d bindings, want %d", got, want)
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report.txt: %v", err)
	}
	for _, w := range []string{"DeveloperRead", "DeveloperWrite", "Rejected", "User:legacy-importer"} {
		if !strings.Contains(string(reportData), w) {
			t.Errorf("report.txt missing %q:\n%s", w, reportData)
		}
	}

	// 3. apply --confirm against the real MDS.
	if exit := cli.Execute(append([]string{"apply", "--plan", planPath, "--confirm"}, mdsArgs...)); exit != 0 {
		t.Fatalf("apply exit %d", exit)
	}

	// 4. verify --mode bindings-exist (poll: MDS's rolebindings cache lags).
	beVerify := append([]string{"verify", "--plan", planPath, "--mode", "bindings-exist", "--out", verifyPath}, mdsArgs...)
	pollUntil(30*time.Second, func() bool {
		cli.Execute(beVerify)
		return bindingsAllExist(verifyPath, want)
	})
	assertBindingsExist(t, verifyPath, planPath, want)

	// 5. verify --mode effective: every source ACL's operation is really granted
	// by the role it converted to.
	effPath := filepath.Join(dir, "verify-effective.json")
	effVerify := append([]string{"verify", "--plan", planPath, "--mode", "effective", "--out", effPath}, mdsArgs...)
	pollUntil(30*time.Second, func() bool {
		cli.Execute(effVerify)
		return effectiveAllOK(effPath)
	})
	assertEffectiveOK(t, effPath)

	// 6. delete-acls: now that every source ACL is EFFECTIVE_OK, remove them from
	// the real broker and confirm they're gone — the destructive end of the
	// migration, gated on the live verify.
	runDeleteRoundTrip(ctx, t, stack, dir, planPath, effPath)
}

// runDeleteRoundTrip runs `delete-acls` in script mode against the live stack,
// executes the generated delete-acls.sh INSIDE the cp-server container (against
// the SASL INTERNAL listener, since the host CLIENT advertised address isn't
// reachable in-container), and asserts the deleted principals' source ACLs are
// gone from the broker while the untouched DENY survives.
func runDeleteRoundTrip(ctx context.Context, t *testing.T, stack mdstest.Stack, dir, planPath, effPath string) {
	t.Helper()
	hostBootstrap := strings.Join(stack.Brokers, ",")
	deletePrincipals := allowPrincipalsOf(complexScenarios)

	adm, closeAdm := newSASLAdmin(t, stack.Brokers)
	defer closeAdm()

	before := 0
	for _, p := range deletePrincipals {
		before += principalACLCount(ctx, t, adm, p, false)
	}
	if before == 0 {
		t.Fatalf("pre-delete: expected source ACLs for %v, found none", deletePrincipals)
	}

	// Generate delete-acls.sh + rollback.sh (gated on EFFECTIVE_OK in effPath).
	args := []string{
		"delete-acls", "--plan", planPath, "--verify", effPath,
		"--bootstrap-server", hostBootstrap, "--command-config", stack.CommandConfig,
		"--confirm", "--i-understand-this-is-destructive",
	}
	for _, p := range deletePrincipals {
		args = append(args, "--principal", p)
	}
	if exit := cli.Execute(args); exit != 0 {
		t.Fatalf("delete-acls exit %d", exit)
	}

	// Rewrite the script to run in-container: bootstrap → the SASL INTERNAL
	// listener (kafka:9092), the host command-config path → a copied-in props
	// file, and the LOG path → a writable /tmp location.
	const internalBootstrap = "kafka:9092"
	const containerCmdCfg = "/tmp/diag.properties"
	scriptBytes, err := os.ReadFile(filepath.Join(dir, "delete-acls.sh"))
	if err != nil {
		t.Fatalf("read delete-acls.sh: %v", err)
	}
	rewritten := rewriteDeleteScript(string(scriptBytes), hostBootstrap, internalBootstrap, stack.CommandConfig, containerCmdCfg)
	if !strings.Contains(rewritten, internalBootstrap) || !strings.Contains(rewritten, containerCmdCfg) {
		t.Fatalf("rewrite missed a substitution; script:\n%s", rewritten)
	}

	props, err := os.ReadFile(stack.CommandConfig)
	if err != nil {
		t.Fatalf("read command-config: %v", err)
	}
	if err := stack.Kafka.CopyToContainer(ctx, props, containerCmdCfg, 0o644); err != nil {
		t.Fatalf("copy props into container: %v", err)
	}
	if err := stack.Kafka.CopyToContainer(ctx, []byte(rewritten), "/tmp/delete-acls.sh", 0o755); err != nil {
		t.Fatalf("copy delete-acls.sh into container: %v", err)
	}

	// plan.json isn't in the container, so the script's fail-closed plan.sha256
	// guard is skipped here (its behaviour is proven in delete/common tests).
	code, reader, err := stack.Kafka.Exec(ctx,
		[]string{"sh", "-c", "MONEDULA_SKIP_PLAN_HASH_CHECK=1 bash /tmp/delete-acls.sh"}, tcexec.Multiplexed())
	if err != nil {
		t.Fatalf("exec delete-acls.sh: %v", err)
	}
	out, _ := io.ReadAll(reader)
	if code != 0 {
		t.Fatalf("delete-acls.sh exit=%d\noutput:\n%s\n/tmp/delete.log:\n%s",
			code, out, containerCat(ctx, t, stack.Kafka, "/tmp/delete.log"))
	}

	// Every deleted principal's source ACLs must be gone; the DENY (not targeted)
	// must survive — proving the deletion was correctly scoped.
	for _, p := range deletePrincipals {
		if n := principalACLCount(ctx, t, adm, p, false); n != 0 {
			t.Errorf("post-delete: %s still has %d ALLOW ACL(s)", p, n)
		}
	}
	if n := principalACLCount(ctx, t, adm, "User:legacy-importer", true); n != 1 {
		t.Errorf("DENY ACL for User:legacy-importer should survive deletion (have %d, want 1)", n)
	}
}

// rewriteDeleteScript adjusts the generated script's host-bound bootstrap,
// command-config path, and LOG path so it runs inside the cp-server container.
func rewriteDeleteScript(script, hostBootstrap, internalBootstrap, hostCmdCfg, containerCmdCfg string) string {
	out := strings.ReplaceAll(script, hostBootstrap, internalBootstrap)
	out = strings.ReplaceAll(out, hostCmdCfg, containerCmdCfg)
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "LOG=") {
			out = strings.Replace(out, line, "LOG=/tmp/delete.log", 1)
			break
		}
	}
	return out
}

// newSASLAdmin builds a kadm client authenticated as the kafka superuser over
// the host CLIENT (SASL_PLAINTEXT) listener.
func newSASLAdmin(t *testing.T, brokers []string) (*kadm.Client, func()) {
	t.Helper()
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.SASL(plain.Auth{User: mdstest.KafkaUser, Pass: mdstest.KafkaPass}.AsMechanism()),
	)
	if err != nil {
		t.Fatalf("kgo client: %v", err)
	}
	return kadm.NewClient(cl), func() { cl.Close() }
}

// principalACLCount counts a principal's ACL entries of one permission type
// (deny=false → ALLOW, deny=true → DENY) across every resource type. The
// pattern-type filter is ANY (mandatory for Confluent, which rejects UNKNOWN).
func principalACLCount(ctx context.Context, t *testing.T, adm *kadm.Client, principal string, deny bool) int {
	t.Helper()
	b := kadm.NewACLs().AnyResource().ResourcePatternType(kadm.ACLPatternAny).Operations(kadm.OpAny)
	if deny {
		b = b.Deny(principal).DenyHosts()
	} else {
		b = b.Allow(principal).AllowHosts()
	}
	res, err := adm.DescribeACLs(ctx, b)
	if err != nil {
		t.Fatalf("DescribeACLs(%s): %v", principal, err)
	}
	n := 0
	for _, r := range res {
		if r.Err != nil {
			t.Fatalf("DescribeACLs(%s) result err: %v", principal, r.Err)
		}
		n += len(r.Described)
	}
	return n
}

// containerCat returns the contents of a file inside the container, best-effort.
func containerCat(ctx context.Context, t *testing.T, c tcgo.Container, path string) string {
	t.Helper()
	_, r, err := c.Exec(ctx, []string{"sh", "-c", "cat " + path + " 2>/dev/null || echo '(no log)'"}, tcexec.Multiplexed())
	if err != nil {
		return "(exec err)"
	}
	out, _ := io.ReadAll(r)
	return string(out)
}

// runAllOpPipeline drives the All-op scenarios (ResourceOwner / SystemAdmin)
// through extract → plan → apply → verify bindings-exist. These can't be
// effective-verified (an `All` source op never matches a role's concrete
// allowedOperations), so bindings-exist is the right and only check.
func runAllOpPipeline(ctx context.Context, t *testing.T, stack mdstest.Stack, mdsArgs []string) {
	t.Helper()
	dir := t.TempDir()
	aclsPath := filepath.Join(dir, "acls.json")
	scopesPath := filepath.Join(dir, "scopes.yaml")
	planPath := filepath.Join(dir, "plan.json")
	verifyPath := filepath.Join(dir, "verify.json")
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: "+stack.ClusterID+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := countAllowBindings(allOpScenarios)

	extractArgs := append([]string{
		"extract", "--from", "live",
		"--bootstrap-server", strings.Join(stack.Brokers, ","),
		"--command-config", stack.CommandConfig,
		"--out", aclsPath,
	}, principalFilterArgs(principalsOf(allOpScenarios))...)
	if exit := cli.Execute(extractArgs); exit != 0 {
		t.Fatalf("extract (all-op) exit %d", exit)
	}
	assertExtractedACLs(t, aclsPath, allOpScenarios)

	if exit := cli.Execute([]string{
		"plan", "--acls", aclsPath, "--scopes", scopesPath, "--out", planPath,
	}); exit != 0 {
		t.Fatalf("plan (all-op) exit %d", exit)
	}
	if got := planBindingCount(t, planPath); got != want {
		t.Fatalf("all-op plan produced %d bindings, want %d", got, want)
	}

	if exit := cli.Execute(append([]string{"apply", "--plan", planPath, "--confirm"}, mdsArgs...)); exit != 0 {
		t.Fatalf("apply (all-op) exit %d", exit)
	}

	beVerify := append([]string{"verify", "--plan", planPath, "--mode", "bindings-exist", "--out", verifyPath}, mdsArgs...)
	pollUntil(30*time.Second, func() bool {
		cli.Execute(beVerify)
		return bindingsAllExist(verifyPath, want)
	})
	assertBindingsExist(t, verifyPath, planPath, want)
}

// pollUntil calls fn until it returns true or the deadline elapses, sleeping a
// second between attempts.
func pollUntil(d time.Duration, fn func() bool) {
	for deadline := time.Now().Add(d); ; {
		if fn() || time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Second)
	}
}

// principalFilterArgs expands principals into repeated --principal-filter flags.
func principalFilterArgs(principals []string) []string {
	var a []string
	for _, p := range principals {
		a = append(a, "--principal-filter", p)
	}
	return a
}

// assertExtractedACLs parses acls.json and asserts every expected (principal,
// operation, resource, pattern, permission) row a scenario should produce is
// present — a structured check that a real extract regression would trip,
// unlike a substring scan.
func assertExtractedACLs(t *testing.T, aclsPath string, scenarios []scenario) {
	t.Helper()
	var doc struct {
		Acls []struct {
			Principal      string `json:"principal"`
			Operation      string `json:"operation"`
			ResourceType   string `json:"resource_type"`
			ResourceName   string `json:"resource_name"`
			PatternType    string `json:"pattern_type"`
			PermissionType string `json:"permission_type"`
		} `json:"acls"`
	}
	if !readJSON(aclsPath, &doc) {
		t.Fatalf("read/parse %s", aclsPath)
	}
	type row struct{ principal, op, rtype, name, pattern, perm string }
	have := map[row]bool{}
	for _, a := range doc.Acls {
		have[row{a.Principal, a.Operation, a.ResourceType, a.ResourceName, a.PatternType, a.PermissionType}] = true
	}
	for _, s := range scenarios {
		perm := string(types.PermissionAllow)
		if s.deny {
			perm = string(types.PermissionDeny)
		}
		for _, op := range s.ops {
			w := row{s.principal, string(opName(op)), string(s.resType), s.name, string(patternType(s)), perm}
			if !have[w] {
				t.Errorf("acls.json missing expected row %+v", w)
			}
		}
	}
}

// createScenarioACLs writes the given scenarios onto the broker via kadm. It
// waits for the broker to answer, then issues one CreateACLs per scenario. If
// the broker rejects ACL management the test is skipped, not failed.
func createScenarioACLs(ctx context.Context, t *testing.T, brokers []string, kafka tcgo.Container, scenarios []scenario) {
	t.Helper()
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		// The CLIENT listener is SASL_PLAINTEXT/PLAIN; authenticate as the kafka
		// superuser so ConfluentServerAuthorizer permits ACL management.
		kgo.SASL(plain.Auth{User: mdstest.KafkaUser, Pass: mdstest.KafkaPass}.AsMechanism()),
	)
	if err != nil {
		t.Fatalf("kgo client: %v", err)
	}
	defer cl.Close()
	adm := kadm.NewClient(cl)

	// First confirm the host port is actually published — a raw TCP dial
	// distinguishes "Docker never bound the advertised port" from a Kafka-layer
	// problem. Then wait for the PLAINTEXT listener to answer a cheap describe.
	tcpOK := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		conn, derr := net.DialTimeout("tcp", brokers[0], 2*time.Second)
		if derr == nil {
			conn.Close()
			tcpOK = true
			break
		}
		time.Sleep(time.Second)
	}
	if !tcpOK {
		t.Skipf("broker %v: host port never accepted a TCP connection (port publish failed)", brokers)
	}

	ready := false
	var lastErr error
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); {
		dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
		// ResourcePatternType(ACLPatternAny) is mandatory: a describe filter that
		// leaves the pattern type UNKNOWN(0) is rejected by Confluent's stricter
		// DescribeAclsRequest.normalizeAndValidate (vanilla Kafka tolerates it).
		_, derr := adm.DescribeACLs(dctx, kadm.NewACLs().
			AnyResource().ResourcePatternType(kadm.ACLPatternAny).
			Operations(kadm.OpAny).Allow().AllowHosts().Deny().DenyHosts())
		dcancel()
		if derr == nil {
			ready = true
			break
		}
		lastErr = derr
		time.Sleep(time.Second)
	}
	if !ready {
		dumpBrokerDiag(ctx, t, kafka)
		t.Skipf("broker %v did not accept a DescribeACLs within 60s (last err: %v); skipping", brokers, lastErr)
	}

	for _, s := range scenarios {
		b := kadm.NewACLs().Operations(s.ops...)
		if s.prefixed {
			b = b.ResourcePatternType(kadm.ACLPatternPrefixed)
		} else {
			b = b.ResourcePatternType(kadm.ACLPatternLiteral)
		}
		if s.deny {
			b = b.Deny(s.principal).DenyHosts("*")
		} else {
			b = b.Allow(s.principal).AllowHosts("*")
		}
		switch s.resType {
		case types.ResourceGroup:
			b = b.Groups(s.name)
		case types.ResourceCluster:
			b = b.Clusters()
		default:
			b = b.Topics(s.name)
		}
		res, err := adm.CreateACLs(ctx, b)
		if err != nil {
			t.Fatalf("CreateACLs(%s %s:%s): %v", s.principal, s.resType, s.name, err)
		}
		for _, r := range res {
			if r.Err != nil {
				t.Skipf("CreateACLs returned %v — broker may not have ACL security enabled; skipping", r.Err)
			}
		}
	}
}

// dumpBrokerDiag prints, from inside the cp-server container, which TCP ports
// are actually listening and whether the in-container PLAINTEXT listener serves
// ACL reads — this distinguishes a host→container port-publish problem from the
// broker never binding 9094 (or rejecting ANONYMOUS). Best-effort; never fails.
func dumpBrokerDiag(ctx context.Context, t *testing.T, kafka tcgo.Container) {
	t.Helper()
	if kafka == nil {
		return
	}
	exec := func(label string, cmd []string) {
		code, r, err := kafka.Exec(ctx, cmd)
		if err != nil {
			t.Logf("diag %s: exec err: %v", label, err)
			return
		}
		out, _ := io.ReadAll(r)
		t.Logf("diag %s (exit %d):\n%s", label, code, out)
	}
	// Can the kafka superuser read ACLs over the in-container INTERNAL SASL
	// listener (kafka:9092, container-reachable so not poisoned by the host-port
	// advertised address)? Confirms the broker's ACL API is alive and that the
	// failure is host-side rather than a dead broker.
	exec("sasl-acl-list", []string{"bash", "-c",
		`printf 'security.protocol=SASL_PLAINTEXT\nsasl.mechanism=PLAIN\nsasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="kafka" password="kafka-secret";\n' > /tmp/diag.properties && kafka-acls --bootstrap-server kafka:9092 --command-config /tmp/diag.properties --list 2>&1 | tail -20`})
	// Filter the FULL broker log (container stdout) for ACL-handler /
	// authorization exceptions — the state-change TRACE flood otherwise buries
	// them in a plain tail.
	if rc, err := kafka.Logs(ctx); err == nil {
		defer rc.Close()
		b, _ := io.ReadAll(rc)
		var hits []string
		for _, line := range strings.Split(string(b), "\n") {
			ll := strings.ToLower(line)
			if strings.Contains(ll, "state.change") || strings.Contains(ll, "cruise") {
				continue
			}
			if strings.Contains(line, "ERROR") || strings.Contains(ll, "exception") ||
				strings.Contains(ll, "acl") || strings.Contains(ll, "authoriz") {
				hits = append(hits, line)
			}
		}
		if len(hits) > 40 {
			hits = hits[len(hits)-40:]
		}
		t.Logf("diag cp-server log (acl/error lines):\n%s", strings.Join(hits, "\n"))
	}
}

func planBindingCount(t *testing.T, planPath string) int {
	t.Helper()
	data, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Bindings []json.RawMessage `json:"bindings"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	return len(p.Bindings)
}

// bindingsAllExist is the poll predicate for bindings-exist verification: every
// planned binding present, none missing or unknown.
func bindingsAllExist(verifyPath string, want int) bool {
	var v struct {
		Counts struct {
			BindingExists  int `json:"binding_exists"`
			BindingMissing int `json:"binding_missing"`
			BindingUnknown int `json:"binding_unknown"`
		} `json:"counts"`
	}
	if !readJSON(verifyPath, &v) {
		return false
	}
	return v.Counts.BindingExists == want && v.Counts.BindingMissing == 0 && v.Counts.BindingUnknown == 0
}

func assertBindingsExist(t *testing.T, verifyPath, planPath string, want int) {
	t.Helper()
	var v struct {
		Results []struct {
			BindingID string `json:"binding_id"`
			Status    string `json:"status"`
			Detail    string `json:"detail"`
		} `json:"results"`
		Counts struct {
			BindingExists  int `json:"binding_exists"`
			BindingMissing int `json:"binding_missing"`
			BindingUnknown int `json:"binding_unknown"`
		} `json:"counts"`
	}
	if !readJSON(verifyPath, &v) {
		t.Fatalf("read %s", verifyPath)
	}
	if v.Counts.BindingExists != want || v.Counts.BindingMissing != 0 || v.Counts.BindingUnknown != 0 {
		byID := planBindingsByID(planPath)
		var bad []string
		for _, r := range v.Results {
			if r.Status != "BINDING_EXISTS" {
				bad = append(bad, fmt.Sprintf("%s=%s [%s] %s", r.Status, r.BindingID, byID[r.BindingID], r.Detail))
			}
		}
		t.Fatalf("bindings not all present in MDS: exists=%d missing=%d unknown=%d (want exists=%d); not-exists:\n  %s",
			v.Counts.BindingExists, v.Counts.BindingMissing, v.Counts.BindingUnknown, want, strings.Join(bad, "\n  "))
	}
}

// planBindingsByID maps each plan binding ID to a "principal role res:name/pattern"
// summary so a verify failure names the actual resources, not opaque hashes.
func planBindingsByID(planPath string) map[string]string {
	var p struct {
		Bindings []struct {
			ID               string `json:"id"`
			Principal        string `json:"principal"`
			Role             string `json:"role"`
			ResourcePatterns []struct {
				ResourceType string `json:"resource_type"`
				Name         string `json:"name"`
				PatternType  string `json:"pattern_type"`
			} `json:"resource_patterns"`
		} `json:"bindings"`
	}
	out := map[string]string{}
	if !readJSON(planPath, &p) {
		return out
	}
	for _, b := range p.Bindings {
		var rs []string
		for _, rp := range b.ResourcePatterns {
			rs = append(rs, fmt.Sprintf("%s:%s/%s", rp.ResourceType, rp.Name, rp.PatternType))
		}
		out[b.ID] = fmt.Sprintf("%s %s %s", b.Principal, b.Role, strings.Join(rs, ","))
	}
	return out
}

func effectiveAllOK(verifyPath string) bool {
	var v struct {
		Counts struct {
			Total            int `json:"total"`
			EffectiveOK      int `json:"effective_ok"`
			EffectiveMissing int `json:"effective_missing"`
			EffectiveUnknown int `json:"effective_unknown"`
		} `json:"counts"`
	}
	if !readJSON(verifyPath, &v) {
		return false
	}
	return v.Counts.Total > 0 && v.Counts.EffectiveOK == v.Counts.Total &&
		v.Counts.EffectiveMissing == 0 && v.Counts.EffectiveUnknown == 0
}

func assertEffectiveOK(t *testing.T, verifyPath string) {
	t.Helper()
	var v struct {
		Results []struct {
			BindingID   string `json:"binding_id"`
			SourceACLID int    `json:"source_acl_id"`
			Status      string `json:"status"`
			Detail      string `json:"detail"`
		} `json:"results"`
		Counts struct {
			Total            int `json:"total"`
			EffectiveOK      int `json:"effective_ok"`
			EffectiveMissing int `json:"effective_missing"`
			EffectiveUnknown int `json:"effective_unknown"`
		} `json:"counts"`
	}
	if !readJSON(verifyPath, &v) {
		t.Fatalf("read %s", verifyPath)
	}
	if !effectiveAllOK(verifyPath) {
		var bad []string
		for _, r := range v.Results {
			if r.Status != "EFFECTIVE_OK" {
				bad = append(bad, fmt.Sprintf("%s binding=%s src=%d %s", r.Status, r.BindingID, r.SourceACLID, r.Detail))
			}
		}
		t.Fatalf("effective verify not all OK: total=%d ok=%d missing=%d unknown=%d; not-ok:\n  %s",
			v.Counts.Total, v.Counts.EffectiveOK, v.Counts.EffectiveMissing, v.Counts.EffectiveUnknown, strings.Join(bad, "\n  "))
	}
}

func readJSON(path string, v interface{}) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(data, v) == nil
}
