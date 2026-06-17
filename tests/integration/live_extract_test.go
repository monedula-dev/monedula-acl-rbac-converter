// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build integration

// Package integration_test exercises the live extractor against a real
// confluentinc/cp-kafka container. Gated behind `-tags integration` so
// it doesn't run in the default `go test ./...` (which would fail with
// "Docker not available" in most local dev environments).
//
// Run locally:
//
//	go test -count=1 -tags integration ./tests/integration/...
package integration_test

import (
	"context"
	"encoding/json"
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
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestLiveExtract_AgainstCpKafka brings up a real cp-kafka container,
// creates a small ACL set via kadm, runs the binary's `extract --from
// live` against the broker, and asserts the produced acls.json contains
// the expected rows.
//
// cp-kafka requires KAFKA_AUTHORIZER_CLASS_NAME=StandardAuthorizer for
// DescribeACLs to function; without it the broker returns SECURITY_DISABLED
// (for CreateACLs) or closes the connection (for DescribeACLs with UNKNOWN
// ResourcePatternType). We set KAFKA_SUPER_USERS=User:ANONYMOUS so the
// unauthenticated PLAINTEXT connection is treated as a superuser and all ACL
// operations succeed without requiring SASL.
func TestLiveExtract_AgainstCpKafka(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	c, err := kafka.Run(ctx,
		// Bump in lockstep with Confluent Platform releases; current
		// stable line is 7.9.x. The integration suite is opt-in (manual
		// dispatch / `run-integration` label), so the cost of a missed
		// bump is low.
		"confluentinc/cp-kafka:7.9.7",
		kafka.WithClusterID("test-cluster"),
		// Enable the StandardAuthorizer so that CreateACLs / DescribeACLs
		// work. Without this Kafka returns SECURITY_DISABLED for all ACL RPCs
		// or closes the connection on DescribeACLs.
		// KAFKA_SUPER_USERS=User:ANONYMOUS grants the unauthenticated PLAINTEXT
		// connection full access so the test doesn't require SASL.
		tcgo.WithEnv(map[string]string{
			"KAFKA_AUTHORIZER_CLASS_NAME":          "org.apache.kafka.metadata.authorizer.StandardAuthorizer",
			"KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND": "true",
			"KAFKA_SUPER_USERS":                    "User:ANONYMOUS",
		}),
	)
	if err != nil {
		t.Skipf("Docker / cp-kafka unavailable: %v", err)
	}
	defer func() {
		if err := c.Terminate(ctx); err != nil {
			t.Logf("container terminate: %v", err)
		}
	}()

	brokers, err := c.Brokers(ctx)
	if err != nil {
		t.Fatalf("brokers: %v", err)
	}
	t.Logf("cp-kafka brokers: %v", brokers)

	// Create ACLs via kadm.
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
	results, err := adm.CreateACLs(ctx, builder)
	// Close the kadm/kgo client before running extract.
	cl.Close()
	if err != nil {
		t.Fatalf("CreateACLs: %v", err)
	}
	for _, r := range results {
		if r.Err != nil {
			t.Skipf("CreateACLs returned %v — broker may have ACL security disabled; skipping", r.Err)
		}
	}
	t.Logf("Created %d ACL rows for User:alice on orders", len(results))

	// Run extract.
	tmp := t.TempDir()
	out := filepath.Join(tmp, "acls.json")
	exit := cli.Execute([]string{
		"extract", "--from", "live",
		"--bootstrap-server", strings.Join(brokers, ","),
		"--out", out,
	})
	if exit != 0 {
		t.Fatalf("extract exit %d", exit)
	}

	// Read and assert.
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read acls.json: %v", err)
	}
	var set types.ACLSet
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatalf("parse acls.json: %v\n%s", err, data)
	}
	if len(set.ACLs) < 2 {
		t.Errorf("expected at least 2 ACL rows (alice on orders Read+Describe); got %d:\n%s", len(set.ACLs), data)
	}
	var sawAlice bool
	for _, row := range set.ACLs {
		if row.Principal == "User:alice" && row.ResourceName == "orders" {
			sawAlice = true
			break
		}
	}
	if !sawAlice {
		t.Errorf("never saw User:alice on Topic:orders in extracted ACLs:\n%s", data)
	}
}
