// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestExisting_SkipsAlreadyApplied(t *testing.T) {
	// Pre-existing binding matches exactly what the plan would produce.
	existing := []types.Binding{{
		Principal: "User:alice",
		Role:      "DeveloperRead",
		Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
		}},
	}}
	in := plan.Input{
		ACLs:             basicSet(),
		Rules:            basicRules(t),
		Principals:       config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:           types.Scope{KafkaCluster: "lkc-kafka01"},
		ExistingBindings: existing,
	}

	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.Bindings) != 1 {
		t.Fatalf("got %d bindings", len(p.Bindings))
	}
	if p.Bindings[0].Action != types.ActionSkipExists {
		t.Errorf("action: got %q, want SKIP_EXISTS", p.Bindings[0].Action)
	}
}

// TestExisting_EquivalentWinsRegardlessOfOrder pins that when the MDS
// inventory holds BOTH an equivalent binding and another same-principal/role
// binding on different resources, the planner classifies SKIP_EXISTS — never
// CONFLICTING_EXISTING_BINDING — no matter what order MDS returned them in.
// One principal commonly holds the same role on several resource sets, so the
// inventory order is not under the planner's control.
func TestExisting_EquivalentWinsRegardlessOfOrder(t *testing.T) {
	equivalent := types.Binding{
		Principal: "User:alice",
		Role:      "DeveloperRead",
		Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
		}},
	}
	other := types.Binding{
		Principal: "User:alice",
		Role:      "DeveloperRead",
		Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic, Name: "shipments", PatternType: types.PatternLiteral,
		}},
	}

	for _, tc := range []struct {
		name     string
		existing []types.Binding
	}{
		{"equivalent-first", []types.Binding{equivalent, other}},
		{"other-first", []types.Binding{other, equivalent}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := plan.Input{
				ACLs:             basicSet(),
				Rules:            basicRules(t),
				Principals:       config.Principals{Fallback: config.PrincipalFallbackPassThrough},
				Scopes:           types.Scope{KafkaCluster: "lkc-kafka01"},
				ExistingBindings: tc.existing,
			}
			p, err := plan.Run(in)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if len(p.Bindings) != 1 || p.Bindings[0].Action != types.ActionSkipExists {
				t.Fatalf("want one SKIP_EXISTS binding; got bindings=%+v unmapped=%+v", p.Bindings, p.Unmapped)
			}
		})
	}
}

func TestExisting_ConflictGoesToUnmapped(t *testing.T) {
	// MDS already has a binding for (alice, DeveloperRead, kafka-cluster) but
	// with a different resource set — v1 won't modify it.
	existing := []types.Binding{{
		Principal: "User:alice",
		Role:      "DeveloperRead",
		Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic, Name: "shipments", PatternType: types.PatternLiteral,
		}},
	}}
	in := plan.Input{
		ACLs:             basicSet(), // wants orders, not shipments
		Rules:            basicRules(t),
		Principals:       config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:           types.Scope{KafkaCluster: "lkc-kafka01"},
		ExistingBindings: existing,
	}

	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.Unmapped) == 0 {
		t.Errorf("conflict should produce an Unmapped entry")
	}
	if p.Unmapped[0].Reason != "CONFLICTING_EXISTING_BINDING" {
		t.Errorf("reason: got %q, want CONFLICTING_EXISTING_BINDING", p.Unmapped[0].Reason)
	}

	foundWarn := false
	for _, w := range p.Warnings {
		if w.Code == "CONFLICTING_EXISTING_BINDING" {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Errorf("expected CONFLICTING_EXISTING_BINDING warning")
	}
}
