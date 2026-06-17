// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan_test

import (
	"strings"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func basicSet() types.ACLSet {
	return types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{
			{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
			{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		},
	}
}

// loneOpSet builds an ACLSet with a single ACL row for the given op/permission
// on Topic:orders for User:writer.
func loneOpSet(op types.Operation, perm types.PermissionType) types.ACLSet {
	return types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{
			{ID: 1, Principal: "User:writer", Host: "*", Operation: op, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: perm},
		},
	}
}

// TestRun_LoneWriteMapsToDeveloperWrite pins that a single Allow Write ACL
// (with no explicit Describe row) still maps to DeveloperWrite: Kafka implies
// Describe from Write, so normalization expands {Write} -> {Write, Describe}
// and the [Write, Describe] default rule matches. The binding's source_acl_ids
// must reference only the real Write row (the implied Describe invents no ID).
func TestRun_LoneWriteMapsToDeveloperWrite(t *testing.T) {
	in := plan.Input{
		ACLs:       loneOpSet(types.OpWrite, types.PermissionAllow),
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}

	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.Bindings) != 1 {
		t.Fatalf("got %d bindings, want 1; unmapped=%v", len(p.Bindings), p.Unmapped)
	}
	if got := p.Bindings[0].Role; got != "DeveloperWrite" {
		t.Errorf("role: got %q, want DeveloperWrite", got)
	}
	if ids := p.Bindings[0].SourceACLIDs; len(ids) != 1 || ids[0] != 1 {
		t.Errorf("source IDs: got %v, want [1]", ids)
	}
	if len(p.Unmapped) != 0 {
		t.Errorf("unmapped should be empty; got %v", p.Unmapped)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("a clean lone-Write conversion should not warn; got %v", p.Warnings)
	}
}

// TestRun_LoneReadMapsToDeveloperRead is the read-side counterpart.
func TestRun_LoneReadMapsToDeveloperRead(t *testing.T) {
	in := plan.Input{
		ACLs:       loneOpSet(types.OpRead, types.PermissionAllow),
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.Bindings) != 1 || p.Bindings[0].Role != "DeveloperRead" {
		t.Fatalf("expected one DeveloperRead binding; got bindings=%v unmapped=%v", p.Bindings, p.Unmapped)
	}
}

// TestRun_LoneDenyWriteNotExpanded guards the safety boundary: a DENY Write is
// rejected as a DENY and must NOT have an implied Describe fabricated into it.
// The rejected detail therefore mentions only Write.
func TestRun_LoneDenyWriteNotExpanded(t *testing.T) {
	in := plan.Input{
		ACLs:       loneOpSet(types.OpWrite, types.PermissionDeny),
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.Bindings) != 0 {
		t.Errorf("a DENY produces no binding; got %v", p.Bindings)
	}
	if len(p.Rejected) != 1 {
		t.Fatalf("expected 1 rejected DENY; got %v", p.Rejected)
	}
	if d := p.Rejected[0].Detail; strings.Contains(d, "Describe") {
		t.Errorf("DENY Write must not gain an implied Describe; rejected detail = %q", d)
	}
}

// TestRun_ReadWriteTopicEmitsBothRoles is the headline case: a principal that
// holds Read+Write (+Describe) on a topic is both a consumer and a producer.
// A single Developer* role cannot express that, so the planner must emit BOTH
// DeveloperRead and DeveloperWrite — together they reproduce the original
// access. No PARTIAL_RULE_COVERAGE warning should fire, since every operation
// is covered across the two bindings.
func TestRun_ReadWriteTopicEmitsBothRoles(t *testing.T) {
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{
			{ID: 1, Principal: "User:svc-billing", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "billing.", PatternType: types.PatternPrefixed, PermissionType: types.PermissionAllow},
			{ID: 2, Principal: "User:svc-billing", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "billing.", PatternType: types.PatternPrefixed, PermissionType: types.PermissionAllow},
			{ID: 3, Principal: "User:svc-billing", Host: "*", Operation: types.OpWrite, ResourceType: types.ResourceTopic, ResourceName: "billing.", PatternType: types.PatternPrefixed, PermissionType: types.PermissionAllow},
		},
	}
	in := plan.Input{
		ACLs:       set,
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "test"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	roles := map[string]bool{}
	for _, b := range p.Bindings {
		roles[b.Role] = true
		// Each binding targets the same prefixed topic resource.
		if b.ResourcePatterns[0].Name != "billing." || b.ResourcePatterns[0].PatternType != types.PatternPrefixed {
			t.Errorf("unexpected resource on %s binding: %+v", b.Role, b.ResourcePatterns)
		}
	}
	if !roles["DeveloperRead"] || !roles["DeveloperWrite"] {
		t.Fatalf("expected both DeveloperRead and DeveloperWrite; got bindings %v", p.Bindings)
	}
	if len(p.Bindings) != 2 {
		t.Fatalf("expected exactly 2 bindings; got %d: %v", len(p.Bindings), p.Bindings)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("Read+Write is fully covered by two roles; expected no warning, got %v", p.Warnings)
	}
	if len(p.Unmapped) != 0 {
		t.Errorf("unmapped should be empty; got %v", p.Unmapped)
	}
}

// TestRun_AllOnTopicStaysSingleResourceOwner guards the precedence invariant:
// an ALL ACL must still collapse to a single ResourceOwner binding, NOT also
// spawn DeveloperRead/DeveloperWrite. Greedy cover stops as soon as the first
// (highest-priority) rule covers everything.
func TestRun_AllOnTopicStaysSingleResourceOwner(t *testing.T) {
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{
			{ID: 1, Principal: "User:owner", Host: "*", Operation: types.OpAll, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		},
	}
	in := plan.Input{
		ACLs:       set,
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "test"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.Bindings) != 1 || p.Bindings[0].Role != "ResourceOwner" {
		t.Fatalf("ALL on Topic should be a single ResourceOwner binding; got %v", p.Bindings)
	}
}

// topicSet builds an ACLSet for User:p on Topic:t (LITERAL) with one Allow row
// per operation.
func topicSet(ops ...types.Operation) types.ACLSet {
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
	}
	for i, op := range ops {
		set.ACLs = append(set.ACLs, types.ACLRow{
			ID: i + 1, Principal: "User:p", Host: "*", Operation: op,
			ResourceType: types.ResourceTopic, ResourceName: "t",
			PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow,
		})
	}
	return set
}

func runPlan(t *testing.T, set types.ACLSet) types.Plan {
	t.Helper()
	p, err := plan.Run(plan.Input{
		ACLs:       set,
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "test"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return p
}

// TestRun_ProducerWithCreateWarnsOnCreate documents the most common real-world
// producer ACL set: `kafka-acls --producer --topic t` expands to
// Write+Describe+**Create** on the topic. DeveloperWrite grants Write+Describe
// but no default rule grants Create on a (literal) Topic, so Create is reported
// as uncovered rather than silently dropped — the operator decides whether to
// widen to ResourceOwner or rely on the topic already existing.
func TestRun_ProducerWithCreateWarnsOnCreate(t *testing.T) {
	p := runPlan(t, topicSet(types.OpWrite, types.OpDescribe, types.OpCreate))

	if len(p.Bindings) != 1 || p.Bindings[0].Role != "DeveloperWrite" {
		t.Fatalf("expected one DeveloperWrite binding; got %v", p.Bindings)
	}
	var warn *types.Warning
	for i := range p.Warnings {
		if p.Warnings[i].Code == "PARTIAL_RULE_COVERAGE" {
			warn = &p.Warnings[i]
		}
	}
	if warn == nil {
		t.Fatalf("expected PARTIAL_RULE_COVERAGE for the uncovered Create; warnings=%v", p.Warnings)
	}
	if !strings.Contains(warn.Detail, "Create") {
		t.Errorf("warning should name Create; got %q", warn.Detail)
	}
}

// TestRun_ConfigOpComposesResourceOwner documents a greedy-cover edge: a
// principal holding Read AND a config op (DescribeConfigs) on one topic selects
// DeveloperRead first, then ResourceOwner to cover the config op (the only rule
// that does). ResourceOwner already subsumes DeveloperRead, so the extra
// DeveloperRead binding is redundant — a known, accepted consequence of the
// coarse `configs -> ResourceOwner` default rule. No operation is uncovered, so
// there is no warning. Pinned here so the behavior is intentional, not a
// surprise.
func TestRun_ConfigOpComposesResourceOwner(t *testing.T) {
	p := runPlan(t, topicSet(types.OpRead, types.OpDescribe, types.OpDescribeConfigs))

	roles := map[string]bool{}
	for _, b := range p.Bindings {
		roles[b.Role] = true
	}
	if !roles["ResourceOwner"] {
		t.Errorf("a config op should pull in ResourceOwner; got roles %v", roles)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("every op is covered (ResourceOwner covers configs); expected no warning, got %v", p.Warnings)
	}
}

func basicRules(t *testing.T) []config.Rule {
	t.Helper()
	y, _ := config.DefaultRulesYAML()
	r, err := config.ParseRules(y)
	if err != nil {
		t.Fatalf("parse defaults: %v", err)
	}
	return r
}

func TestRun_AllowReadDescribeOnTopic(t *testing.T) {
	in := plan.Input{
		ACLs:       basicSet(),
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}

	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if len(p.Bindings) != 1 {
		t.Fatalf("got %d bindings, want 1", len(p.Bindings))
	}
	b := p.Bindings[0]
	if b.Role != "DeveloperRead" {
		t.Errorf("role: got %q", b.Role)
	}
	if b.Action != types.ActionCreate {
		t.Errorf("action: got %q", b.Action)
	}
	if len(b.SourceACLIDs) != 2 {
		t.Errorf("source IDs: got %d, want 2", len(b.SourceACLIDs))
	}
	if len(p.Unmapped) != 0 {
		t.Errorf("unmapped should be empty; got %v", p.Unmapped)
	}
	if len(p.Rejected) != 0 {
		t.Errorf("rejected should be empty; got %v", p.Rejected)
	}
}

// TestRun_AllowAllOnTopicMapsToResourceOwner pins that an `Allow All` on a
// topic maps to ResourceOwner, not to a narrower role. Normalize expands ALL
// into its implied ops (Read, Write, Describe, ...), so with the default rules
// the planner must still select the [All]->ResourceOwner rule; otherwise it
// silently picks DeveloperRead (Read+Describe) and drops Write/Delete/Alter.
func TestRun_AllowAllOnTopicMapsToResourceOwner(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpAll, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.Bindings) != 1 {
		t.Fatalf("got %d bindings, want 1", len(p.Bindings))
	}
	if p.Bindings[0].Role != "ResourceOwner" {
		t.Errorf("Allow All on Topic must map to ResourceOwner, got %q (narrower role silently drops grants)", p.Bindings[0].Role)
	}
}

// TestRun_PartialRuleCoverageWarns pins that when an operation is covered by
// NO rule at all, the planner emits a PARTIAL_RULE_COVERAGE warning instead of
// silently dropping it. Read+Describe+Delete on a topic matches DeveloperRead
// (Read+Describe); no default rule grants Delete on a topic, so even after
// greedy multi-rule selection Delete stays uncovered and the operator must be
// warned. (Contrast Read+Write, which is now fully covered by DeveloperRead +
// DeveloperWrite — see TestRun_ReadWriteTopicEmitsBothRoles.)
func TestRun_PartialRuleCoverageWarns(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpDelete, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				{ID: 3, Principal: "User:alice", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var got *types.Warning
	for i := range p.Warnings {
		if p.Warnings[i].Code == "PARTIAL_RULE_COVERAGE" {
			got = &p.Warnings[i]
		}
	}
	if got == nil {
		t.Fatalf("expected a PARTIAL_RULE_COVERAGE warning for the uncovered Delete op; warnings=%v", p.Warnings)
	}
	if !strings.Contains(got.Detail, "Delete") {
		t.Errorf("warning should name the uncovered Delete op; got %q", got.Detail)
	}
	// A DeveloperRead binding is still produced for the covered Read+Describe.
	if len(p.Bindings) != 1 || p.Bindings[0].Role != "DeveloperRead" {
		t.Errorf("expected one DeveloperRead binding alongside the warning; got %v", p.Bindings)
	}
}

// TestRun_LoneCreateOnCluster_SuppressedWhenPaired pins that the
// LONE_CREATE_ON_CLUSTER warning does NOT fire when the principal also has a
// prefixed-topic Allow — that is the "paired" case the warning text explicitly
// excludes ("without a paired prefixed-topic ACL").
func TestRun_LoneCreateOnCluster_SuppressedWhenPaired(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpCreate, ResourceType: types.ResourceCluster, ResourceName: "kafka-cluster", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "app-", PatternType: types.PatternPrefixed, PermissionType: types.PermissionAllow},
				{ID: 3, Principal: "User:alice", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "app-", PatternType: types.PatternPrefixed, PermissionType: types.PermissionAllow},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, w := range p.Warnings {
		if w.Code == "LONE_CREATE_ON_CLUSTER" {
			t.Errorf("LONE_CREATE_ON_CLUSTER must not fire when a paired prefixed-topic ACL exists; got %q", w.Detail)
		}
	}
}

// TestRun_LoneCreateOnCluster_NotLone pins that the warning does not fire when
// the Cluster group carries operations besides Create (it is not "lone").
func TestRun_LoneCreateOnCluster_NotLone(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:bob", Host: "*", Operation: types.OpCreate, ResourceType: types.ResourceCluster, ResourceName: "kafka-cluster", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				{ID: 2, Principal: "User:bob", Host: "*", Operation: types.OpClusterAction, ResourceType: types.ResourceCluster, ResourceName: "kafka-cluster", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, w := range p.Warnings {
		if w.Code == "LONE_CREATE_ON_CLUSTER" {
			t.Errorf("LONE_CREATE_ON_CLUSTER must not fire for a non-lone Create (Create+ClusterAction); got %q", w.Detail)
		}
	}
}

// TestRun_LoneCreateOnCluster_Fires keeps the true-positive: a genuinely lone
// Create on Cluster with no paired prefixed-topic ACL still warns.
func TestRun_LoneCreateOnCluster_Fires(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:carol", Host: "*", Operation: types.OpCreate, ResourceType: types.ResourceCluster, ResourceName: "kafka-cluster", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	found := false
	for _, w := range p.Warnings {
		if w.Code == "LONE_CREATE_ON_CLUSTER" {
			found = true
		}
	}
	if !found {
		t.Error("expected LONE_CREATE_ON_CLUSTER for a lone unpaired Create on Cluster")
	}
}

func TestRun_HostRestrictedGoesToUnmapped(t *testing.T) {
	set := basicSet()
	set.ACLs[0].Host = "10.0.0.5"

	in := plan.Input{
		ACLs:       set,
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.Unmapped) == 0 {
		t.Errorf("host-restricted ACL should produce an Unmapped entry")
	}
	found := false
	for _, w := range p.Warnings {
		if w.Code == "HOST_RESTRICTED" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HOST_RESTRICTED warning; got %+v", p.Warnings)
	}
}

func TestRun_UnknownCombinationIsUnmapped(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{{
				ID: 1, Principal: "User:alice", Host: "*",
				Operation: types.OpClusterAction, ResourceType: types.ResourceCluster,
				ResourceName: "kafka-cluster", PatternType: types.PatternLiteral,
				PermissionType: types.PermissionAllow,
			}},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.Unmapped) != 1 {
		t.Errorf("ClusterAction alone should be unmapped; got %d", len(p.Unmapped))
	}
}

func TestRun_MissingKafkaClusterFails(t *testing.T) {
	in := plan.Input{
		ACLs:       basicSet(),
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{}, // missing kafka_cluster
	}
	_, err := plan.Run(in)
	if err == nil {
		t.Fatal("expected error: missing kafka_cluster")
	}
}

func TestRun_PassThroughPrincipalGetsWarning(t *testing.T) {
	in := plan.Input{
		ACLs: types.ACLSet{
			SchemaVersion: "1",
			Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
			ACLs: []types.ACLRow{
				{ID: 1, Principal: "User:CN=svc-bridge,O=acme,C=US", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
				{ID: 2, Principal: "User:CN=svc-bridge,O=acme,C=US", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
			},
		},
		Rules:      basicRules(t),
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	p, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	found := false
	for _, w := range p.Warnings {
		if w.Code == "MTLS_DN_PASS_THROUGH" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected MTLS_DN_PASS_THROUGH warning; got %+v", p.Warnings)
	}
}
