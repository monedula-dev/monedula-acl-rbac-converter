// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package script_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/script"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestEmit_Basic(t *testing.T) {
	plan := types.Plan{
		Bindings: []types.Binding{{
			ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
			Principal: "User:alice", Role: "DeveloperRead",
			Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
			ResourcePatterns: []types.ResourcePattern{{
				ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
			}},
			SourceACLIDs: []int{1, 2},
		}},
	}

	var buf bytes.Buffer
	em := script.New(script.Options{PlanPath: "testdata/basic-plan.json"})
	n, err := em.Emit(&buf, plan)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if n != 1 {
		t.Errorf("created count: got %d, want 1", n)
	}

	out := buf.String()
	for _, want := range []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"confluent iam rbac role-binding create",
		"'User:alice'",
		"'DeveloperRead'",
		"'Topic:orders'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestEmit_PrefixedUsesPrefixFlag pins that a PREFIXED binding is rendered
// with the CLI's --prefix flag and a clean resource value, not a trailing '*'.
// `confluent iam rbac role-binding create` does not parse a trailing '*'; it
// would treat 'Topic:events.*' as a LITERAL binding on a topic literally
// named "events.*".
func TestEmit_PrefixedUsesPrefixFlag(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-cccccccccccc", Action: types.ActionCreate,
		Principal: "User:carol", Role: "DeveloperWrite",
		Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic, Name: "events.", PatternType: types.PatternPrefixed,
		}},
	}}}
	var buf bytes.Buffer
	if _, err := script.New(script.Options{}).Emit(&buf, plan); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "--prefix") {
		t.Errorf("PREFIXED binding must emit --prefix; got:\n%s", out)
	}
	if strings.Contains(out, "events.*") {
		t.Errorf("PREFIXED binding must not append '*' to the resource; got:\n%s", out)
	}
	if !strings.Contains(out, "--resource 'Topic:events.'") {
		t.Errorf("expected clean --resource 'Topic:events.'; got:\n%s", out)
	}
}

// TestEmit_EnvironmentScopeFlag pins that environment scope uses the real
// value-taking --environment flag, not the nonexistent --current-environment
// (which is a boolean in the CLI).
func TestEmit_EnvironmentScopeFlag(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-dddddddddddd", Action: types.ActionCreate,
		Principal: "User:dan", Role: "DeveloperRead",
		Scope: types.Scope{Environment: "env-123", KafkaCluster: "lkc-1"},
	}}}
	var buf bytes.Buffer
	if _, err := script.New(script.Options{}).Emit(&buf, plan); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "--current-environment") {
		t.Errorf("must not emit boolean --current-environment with a value; got:\n%s", out)
	}
	if !strings.Contains(out, "--environment 'env-123'") {
		t.Errorf("expected --environment 'env-123'; got:\n%s", out)
	}
}

// TestEmit_NoNonexistentOrgFlag pins that the nonexistent
// --current-organization flag is never emitted (it would abort the command
// under set -e).
func TestEmit_NoNonexistentOrgFlag(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-eeeeeeeeeeee", Action: types.ActionCreate,
		Principal: "User:eve", Role: "DeveloperRead",
		Scope: types.Scope{Organization: "org-9", KafkaCluster: "lkc-1"},
	}}}
	var buf bytes.Buffer
	if _, err := script.New(script.Options{}).Emit(&buf, plan); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "--current-organization") {
		t.Errorf("must not emit nonexistent --current-organization flag; got:\n%s", buf.String())
	}
}

// TestEmit_CommentNoNewlineInjection pins that a newline in plan-derived data
// cannot escape a generated '#' comment and become an executable line.
func TestEmit_CommentNoNewlineInjection(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-ffffffffffff", Action: types.ActionSkipExists,
		Principal: "User:x\nrm -rf ~", Role: "DeveloperRead",
		Scope: types.Scope{KafkaCluster: "lkc-1"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
		}},
	}}}
	var buf bytes.Buffer
	if _, err := script.New(script.Options{}).Emit(&buf, plan); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\nrm -rf") {
		t.Errorf("newline in principal escaped the comment into an executable line:\n%s", buf.String())
	}
}

func TestEmit_QuotesPrincipal(t *testing.T) {
	plan := types.Plan{
		Bindings: []types.Binding{{
			ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
			Principal: "User:o'malley", Role: "DeveloperRead",
			Scope:            types.Scope{KafkaCluster: "lkc-kafka01"},
			ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral}},
		}},
	}
	var buf bytes.Buffer
	em := script.New(script.Options{})
	if _, err := em.Emit(&buf, plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `'User:o'\''malley'`) {
		t.Errorf("principal not single-quote-escaped:\n%s", buf.String())
	}
}

func TestEmit_SkipExistsCommentedOut(t *testing.T) {
	plan := types.Plan{
		Bindings: []types.Binding{{
			ID: "rb-aaaaaaaaaaaa", Action: types.ActionSkipExists,
			Principal: "User:alice", Role: "DeveloperRead",
			Scope:            types.Scope{KafkaCluster: "lkc-kafka01"},
			ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral}},
		}},
	}
	var buf bytes.Buffer
	em := script.New(script.Options{})
	n, err := em.Emit(&buf, plan)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("created count: got %d, want 0", n)
	}
	if !strings.Contains(buf.String(), "# SKIP") {
		t.Errorf("SKIP_EXISTS should be commented:\n%s", buf.String())
	}
}
