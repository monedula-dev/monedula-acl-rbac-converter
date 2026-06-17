// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cfk_test

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/cfk"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestEmit_Basic(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
		Principal: "User:alice", Role: "DeveloperRead",
		Scope:            types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral}},
	}}}

	var buf bytes.Buffer
	em := cfk.New(cfk.Options{Namespace: "confluent"})
	n, err := em.Emit(&buf, plan)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("count: got %d, want 1", n)
	}
	out := buf.String()
	for _, want := range []string{
		"apiVersion: platform.confluent.io/v1beta1",
		"kind: ConfluentRolebinding",
		"name: rb-aaaaaaaaaaaa",
		"namespace: confluent",
		"type: user",
		"name: alice",
		"role: DeveloperRead",
		"clustersScopeByIds:",
		"kafkaClusterId: lkc-kafka01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "kafkaClusterRef") {
		t.Errorf("must not emit the nonexistent kafkaClusterRef field:\n%s", out)
	}
}

// TestEmit_QuotesUnsafeScalars pins that data-derived scalars containing
// YAML-special characters (here a principal name with ": " and "#") are
// quoted, so the emitted document round-trips to the intended values rather
// than corrupting the CR or injecting keys.
func TestEmit_QuotesUnsafeScalars(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
		Principal: "User:CN=svc, OU=x: y #z", Role: "DeveloperRead",
		Scope:            types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral}},
	}}}
	var buf bytes.Buffer
	if _, err := cfk.New(cfk.Options{}).Emit(&buf, plan); err != nil {
		t.Fatal(err)
	}
	// The emitted YAML must parse back, and the principal name must survive
	// intact through marshal+unmarshal.
	docs := strings.Split(buf.String(), "---")
	var got struct {
		Spec struct {
			Principal struct {
				Name string `yaml:"name"`
			} `yaml:"principal"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(docs[0]), &got); err != nil {
		t.Fatalf("emitted YAML does not parse: %v\n%s", err, buf.String())
	}
	if got.Spec.Principal.Name != "CN=svc, OU=x: y #z" {
		t.Errorf("principal name corrupted by unquoted emission: got %q", got.Spec.Principal.Name)
	}
}

func TestEmit_GroupPrincipalKindGroup(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
		Principal: "Group:billing-services", Role: "DeveloperRead",
		Scope:            types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral}},
	}}}
	var buf bytes.Buffer
	em := cfk.New(cfk.Options{})
	if _, err := em.Emit(&buf, plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "type: group") {
		t.Errorf("Group principal should yield principal.type: group:\n%s", buf.String())
	}
}

// TestEmit_WarnsOnUnrepresentableScope pins that organization/environment
// scope, which the CFK CRD cannot express, produces a visible warning rather
// than being dropped silently.
func TestEmit_WarnsOnUnrepresentableScope(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
		Principal: "User:alice", Role: "DeveloperRead",
		Scope:            types.Scope{Organization: "org-1", KafkaCluster: "lkc-1"},
		ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral}},
	}}}
	var buf bytes.Buffer
	if _, err := cfk.New(cfk.Options{}).Emit(&buf, plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "WARNING") || !strings.Contains(buf.String(), "organization/environment") {
		t.Errorf("expected a warning about unrepresentable org/env scope; got:\n%s", buf.String())
	}
}

func TestEmit_NamespaceEmptyOmitted(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
		Principal: "User:alice", Role: "DeveloperRead",
		Scope:            types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral}},
	}}}
	var buf bytes.Buffer
	em := cfk.New(cfk.Options{Namespace: ""})
	if _, err := em.Emit(&buf, plan); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "namespace:") {
		t.Errorf("namespace should be omitted with empty Namespace; got:\n%s", buf.String())
	}
}
