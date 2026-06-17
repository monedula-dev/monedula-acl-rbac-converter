// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// genACLs returns n synthetic ACL rows split evenly across two-row
// Read+Describe groups that map cleanly to DeveloperRead. Half are
// Topic ACLs, half are Group ACLs. Each principal owns one resource
// to maximise the normalisation cost (lots of small groups, not one
// huge one).
func genACLs(n int) types.ACLSet {
	rows := make([]types.ACLRow, 0, n)
	for i := 0; i < n; i += 2 {
		principal := fmt.Sprintf("User:svc-%04d", i/4)
		resource := fmt.Sprintf("topic-%05d", i/2)
		rType := types.ResourceTopic
		if (i/2)%2 == 1 {
			rType = types.ResourceGroup
		}
		rows = append(rows,
			types.ACLRow{
				ID: i + 1, Principal: principal, Host: "*",
				Operation:    types.OpRead,
				ResourceType: rType, ResourceName: resource,
				PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow,
			},
			types.ACLRow{
				ID: i + 2, Principal: principal, Host: "*",
				Operation:    types.OpDescribe,
				ResourceType: rType, ResourceName: resource,
				PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow,
			},
		)
	}
	return types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-24T00:00:00Z"},
		ACLs:          rows,
	}
}

// BenchmarkPlan_1kACLs is the warm-up case; runs in roughly tens of ms.
func BenchmarkPlan_1kACLs(b *testing.B) {
	benchPlan(b, 1000)
}

// BenchmarkPlan_10kACLs locks in the spec §12 scale target ("batches up to
// ~10,000 ACLs per run"). A regression that pushes plan past O(n log n)
// shows up here as a wall-clock blowup.
func BenchmarkPlan_10kACLs(b *testing.B) {
	benchPlan(b, 10000)
}

func benchPlan(b *testing.B, n int) {
	b.Helper()

	acls := genACLs(n)
	rulesYAML, _ := config.DefaultRulesYAML()
	rules, err := config.ParseRules(rulesYAML)
	if err != nil {
		b.Fatal(err)
	}
	in := plan.Input{
		ACLs:       acls,
		Rules:      rules,
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-bench"},
		Now:        func() time.Time { return time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC) },
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p, err := plan.Run(in)
		if err != nil {
			b.Fatal(err)
		}
		if len(p.Bindings) == 0 {
			b.Fatalf("expected bindings; got 0 (n=%d)", n)
		}
	}
}
