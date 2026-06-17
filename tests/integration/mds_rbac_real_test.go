// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build integration

// Real-MDS end-to-end coverage: drives the production mds.Client and the full
// extract→plan→apply→verify pipeline against a REAL Confluent MDS (cp-server
// with RBAC), not an in-process fake. This is what the MDS wire-contract bugs
// slipped past — the snake_case body, the nonexistent list/lookup endpoints,
// the bad capability probe, the double-escaped path all fail against a real
// server.
//
// The same client is exercised against two Confluent Platform lines:
//   - 7.9.x: ZooKeeper-backed.
//   - 8.2.x: KRaft (ZooKeeper removed in CP 8.0).
//
// Both speak the identical MDS REST contract; only the broker bring-up differs.
// The Docker harness that stands the stack up lives in internal/mdstest. Heavy
// (~3 containers, ~60-90s warm-up per version), so under -tags integration.
package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/internal/mdstest"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestRealMDS_RoleBindingLifecycle drives the production mds.Client through
// create → list → effective-lookup against a real MDS, on every CP version.
func TestRealMDS_RoleBindingLifecycle(t *testing.T) {
	for _, spec := range mdstest.CPSpecs {
		t.Run(spec.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
			defer cancel()

			stack, terminate := mdstest.StartMDSStack(ctx, t, spec)
			defer terminate()
			t.Logf("%s MDS up at %s (cluster %s)", spec.Name, stack.URL, stack.ClusterID)

			scope := types.Scope{KafkaCluster: stack.ClusterID}
			tok, err := mds.ResolveToken(mds.AuthConfig{URL: stack.URL, User: "mds", PasswordFile: stack.PWFile})
			if err != nil {
				t.Fatalf("authenticate to MDS: %v", err)
			}
			cl, err := mds.NewClient(mds.Config{URL: stack.URL, Token: tok.Token, MaxRetries: 2})
			if err != nil {
				t.Fatalf("new client: %v", err)
			}

			if cap, err := mds.ProbeCapability(cl); err != nil || cap != mds.CapabilityLookup {
				t.Fatalf("ProbeCapability = (%v, %v); want (lookup, nil)", cap, err)
			}

			binding := types.Binding{
				Principal: "User:alice",
				Role:      "DeveloperRead",
				Scope:     scope,
				ResourcePatterns: []types.ResourcePattern{{
					ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
				}},
			}
			if err := mds.CreateRoleBinding(cl, binding); err != nil {
				t.Fatalf("CreateRoleBinding against real MDS: %v", err)
			}

			var listed []types.Binding
			for i := 0; i < 20; i++ {
				listed, err = mds.ListBindings(cl, "User:alice", scope)
				if err != nil {
					t.Fatalf("ListBindings: %v", err)
				}
				if hasBinding(listed, "DeveloperRead", "orders") {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			if !hasBinding(listed, "DeveloperRead", "orders") {
				t.Fatalf("created binding not returned by ListBindings; got %+v", listed)
			}

			allowedRead, err := mds.LookupAllowed(cl, "User:alice", types.OpRead, types.ResourceTopic, "orders", types.PatternLiteral, scope)
			if err != nil {
				t.Fatalf("LookupAllowed Read: %v", err)
			}
			if !allowedRead {
				t.Error("LookupAllowed: DeveloperRead on Topic:orders should permit Read")
			}
			allowedWrite, err := mds.LookupAllowed(cl, "User:alice", types.OpWrite, types.ResourceTopic, "orders", types.PatternLiteral, scope)
			if err != nil {
				t.Fatalf("LookupAllowed Write: %v", err)
			}
			if allowedWrite {
				t.Error("LookupAllowed: DeveloperRead must NOT permit Write")
			}
		})
	}
}

func hasBinding(bindings []types.Binding, role, topic string) bool {
	for _, b := range bindings {
		if b.Role != role {
			continue
		}
		for _, p := range b.ResourcePatterns {
			if p.ResourceType == types.ResourceTopic && p.Name == topic {
				return true
			}
		}
	}
	return false
}
