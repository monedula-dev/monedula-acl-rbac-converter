// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tcgo "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
)

// startCpKafka brings up a confluentinc/cp-kafka container with the
// StandardAuthorizer enabled and the anonymous principal as
// superuser, so DescribeACLs / CreateACLs work without SASL. Returns
// the broker addresses and a terminate func.
func startCpKafka(ctx context.Context, t *testing.T) (brokers []string, terminate func()) {
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
	return addrs, func() {
		if err := c.Terminate(ctx); err != nil {
			t.Logf("container terminate: %v", err)
		}
	}
}

// TestFullPipeline_AgainstCpKafkaAndFakeMDS exercises the full
// migration path against a real Kafka broker and an httptest MDS:
//
//	extract --from live → plan → apply → verify → delete-acls (script mode)
//
// This complements tests/e2e/apply_verify_test.go (kfake + httptest) by
// using a real broker, which catches franz-go / wire-protocol drift
// that kfake's canned responses don't surface. delete-acls runs in
// the default script-emission mode so no destructive Kafka call is
// actually issued.
func TestFullPipeline_AgainstCpKafkaAndFakeMDS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	brokers, terminate := startCpKafka(ctx, t)
	defer terminate()
	t.Logf("cp-kafka brokers: %v", brokers)

	// Create the source ACLs via kadm.
	cl, err := kgo.NewClient(kgo.SeedBrokers(brokers...))
	if err != nil {
		t.Fatalf("kgo client: %v", err)
	}
	adm := kadm.NewClient(cl)
	builder := kadm.NewACLs().
		Allow("User:alice").
		AllowHosts("*").
		Topics("orders").
		ResourcePatternType(kadm.ACLPatternLiteral).
		Operations(kadm.OpRead, kadm.OpDescribe)
	res, err := adm.CreateACLs(ctx, builder)
	cl.Close()
	if err != nil {
		t.Fatalf("CreateACLs: %v", err)
	}
	for _, r := range res {
		if r.Err != nil {
			t.Skipf("CreateACLs returned %v — broker may not have ACL security enabled; skipping", r.Err)
		}
	}

	// Stand up the fake MDS.
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

	// 1. extract --from live (against real cp-kafka).
	if exit := cli.Execute([]string{
		"extract", "--from", "live",
		"--bootstrap-server", strings.Join(brokers, ","),
		"--out", aclsPath,
	}); exit != 0 {
		t.Fatalf("extract exit %d", exit)
	}

	// 2. plan.
	if exit := cli.Execute([]string{
		"plan",
		"--acls", aclsPath,
		"--scopes", scopesPath,
		"--out", planPath,
	}); exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}

	// 3. apply --confirm (against httptest MDS).
	if exit := cli.Execute([]string{
		"apply",
		"--plan", planPath,
		"--mds-url", mds.srv.URL,
		"--mds-token-file", tokenPath,
		"--confirm",
	}); exit != 0 {
		t.Fatalf("apply exit %d; MDS requests so far: %v", exit, mds.requests)
	}
	if len(mds.bindings) == 0 {
		t.Errorf("apply created no MDS bindings; requests: %v", mds.requests)
	}

	// 4. verify --mode effective.
	if exit := cli.Execute([]string{
		"verify",
		"--plan", planPath,
		"--mode", "effective",
		"--mds-url", mds.srv.URL,
		"--mds-token-file", tokenPath,
	}); exit != 0 {
		t.Fatalf("verify exit %d", exit)
	}
	verifyData, err := os.ReadFile(verifyPath)
	if err != nil {
		t.Fatalf("read verify.json: %v", err)
	}
	if !strings.Contains(string(verifyData), "EFFECTIVE_OK") {
		t.Errorf("verify.json missing EFFECTIVE_OK:\n%s", verifyData)
	}

	// 5. delete-acls in default script-emission mode. This MUST NOT
	// touch Kafka; the script is generated, written to disk, and the
	// operator inspects/runs it themselves. Asserting the file exists
	// and contains the expected kafka-acls --remove invocation is the
	// integration contract.
	if exit := cli.Execute([]string{
		"delete-acls",
		"--plan", planPath,
		"--verify", verifyPath,
		"--bootstrap-server", strings.Join(brokers, ","),
		"--principal", "User:alice",
		"--confirm", "--i-understand-this-is-destructive",
	}); exit != 0 {
		t.Fatalf("delete-acls exit %d", exit)
	}
	scriptBytes, err := os.ReadFile(deleteScript)
	if err != nil {
		t.Fatalf("read delete-acls.sh: %v", err)
	}
	scriptText := string(scriptBytes)
	for _, want := range []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"kafka-acls",
		"--remove",
		"'User:alice'",
		"'orders'",
	} {
		if !strings.Contains(scriptText, want) {
			t.Errorf("delete-acls.sh missing %q", want)
		}
	}

	// Sanity-check the companion artefacts.
	if _, err := os.Stat(filepath.Join(tmp, "deleted-acls.json")); err != nil {
		t.Errorf("deleted-acls.json missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "rollback.sh")); err != nil {
		t.Errorf("rollback.sh missing: %v", err)
	}

	// MDS request log: at least one POST (apply) and one GET (verify).
	var sawPost, sawLookup bool
	for _, req := range mds.requests {
		if strings.HasPrefix(req, "POST ") {
			sawPost = true
		}
		if strings.Contains(req, "/lookup/") {
			sawLookup = true
		}
	}
	if !sawPost {
		t.Errorf("expected MDS POST from apply; saw %v", mds.requests)
	}
	if !sawLookup {
		t.Errorf("expected MDS lookup from verify; saw %v", mds.requests)
	}
	fmt.Fprintf(os.Stderr, "MDS request log (%d):\n  %s\n", len(mds.requests), strings.Join(mds.requests, "\n  "))
}
