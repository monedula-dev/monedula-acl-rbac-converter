// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestIntegration_BasicAllow(t *testing.T) {
	root := filepath.Join("testdata", "basic-allow")

	aclData, err := os.ReadFile(filepath.Join(root, "acls.json"))
	if err != nil {
		t.Fatal(err)
	}
	var acls types.ACLSet
	if err := json.Unmarshal(aclData, &acls); err != nil {
		t.Fatal(err)
	}

	scopeData, err := os.ReadFile(filepath.Join(root, "scopes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	scope, err := config.ParseScopes(scopeData)
	if err != nil {
		t.Fatal(err)
	}

	defaults, _ := config.DefaultRulesYAML()
	rules, _ := config.ParseRules(defaults)

	in := plan.Input{
		ACLs:       acls,
		Rules:      rules,
		Principals: config.Principals{Fallback: config.PrincipalFallbackPassThrough},
		Scopes:     scope,
		Now:        func() time.Time { return time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC) },
	}

	got, err := plan.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// Binding ID is computed; just check the shape and the other fields.
	if len(got.Bindings) != 1 {
		t.Fatalf("got %d bindings", len(got.Bindings))
	}
	if !regexpBindingID(got.Bindings[0].ID) {
		t.Errorf("binding ID shape: %q", got.Bindings[0].ID)
	}

	expectedData, err := os.ReadFile(filepath.Join(root, "expected-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected types.Plan
	if err := json.Unmarshal(expectedData, &expected); err != nil {
		t.Fatal(err)
	}

	if got.Bindings[0].Role != expected.Bindings[0].Role {
		t.Errorf("role: got %q want %q", got.Bindings[0].Role, expected.Bindings[0].Role)
	}
	if got.Bindings[0].Principal != expected.Bindings[0].Principal {
		t.Errorf("principal: got %q want %q", got.Bindings[0].Principal, expected.Bindings[0].Principal)
	}
	if got.Bindings[0].Scope != expected.Bindings[0].Scope {
		t.Errorf("scope: got %+v want %+v", got.Bindings[0].Scope, expected.Bindings[0].Scope)
	}
	if len(got.Bindings[0].SourceACLIDs) != 2 {
		t.Errorf("source IDs: got %d want 2", len(got.Bindings[0].SourceACLIDs))
	}
}

func regexpBindingID(s string) bool {
	if len(s) != 15 || s[:3] != "rb-" {
		return false
	}
	for _, c := range s[3:] {
		if !(('0' <= c && c <= '9') || ('a' <= c && c <= 'f')) {
			return false
		}
	}
	return true
}
