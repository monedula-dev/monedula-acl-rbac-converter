// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package types_test

import (
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestValidateACLRow is the input-side regression guard for the
// "newline-in-comment-header" shell-script injection class. The generated
// delete-*.sh writes Principal / Host / ResourceName into `#` comment lines
// verbatim, so a '\n' there would escape the comment and run as bash. Schema
// validation accepts those strings as arbitrary JSON strings, so we need a
// separate field-content check.
func TestValidateACLRow(t *testing.T) {
	clean := types.ACLRow{
		ID: 1, Principal: "User:alice", Host: "*",
		Operation: types.OpRead, ResourceType: types.ResourceTopic,
		ResourceName: "orders", PatternType: types.PatternLiteral,
		PermissionType: types.PermissionAllow,
	}

	if err := types.ValidateACLRow(clean); err != nil {
		t.Fatalf("clean row should validate: %v", err)
	}

	cases := []struct {
		name      string
		mutate    func(r *types.ACLRow)
		wantField string // substring that must appear in the error
	}{
		{"principal-newline", func(r *types.ACLRow) { r.Principal = "User:eve\nrm -rf /" }, "principal"},
		{"principal-cr", func(r *types.ACLRow) { r.Principal = "User:eve\r" }, "principal"},
		{"principal-null", func(r *types.ACLRow) { r.Principal = "User:eve\x00" }, "principal"},
		{"principal-tab", func(r *types.ACLRow) { r.Principal = "User:\teve" }, "principal"},
		{"principal-del", func(r *types.ACLRow) { r.Principal = "User:eve\x7f" }, "principal"},
		{"host-newline", func(r *types.ACLRow) { r.Host = "*\necho pwned" }, "host"},
		{"resource-newline", func(r *types.ACLRow) { r.ResourceName = "topic\necho pwned" }, "resource_name"},
		// Shell-meta characters are NOT rejected here — they pass via
		// shell.Quote'ing in the emitter (see the dash_dash_value_is_quoted
		// test in delete/acls). This function only guards the comment-header
		// "%s" interpolation, which doesn't survive a control character.
		{"shell-meta-ok-dollar-paren", func(r *types.ACLRow) { r.ResourceName = "--$(curl evil)" }, ""},
		{"shell-meta-ok-backtick", func(r *types.ACLRow) { r.ResourceName = "`whoami`" }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := clean
			tc.mutate(&r)
			err := types.ValidateACLRow(r)
			if tc.wantField == "" {
				if err != nil {
					t.Errorf("expected ok, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error mentioning %q, got nil", tc.wantField)
			}
			if !strings.Contains(err.Error(), tc.wantField) {
				t.Errorf("error should name the offending field %q; got: %v", tc.wantField, err)
			}
		})
	}
}

// TestValidatePlan is the binding-side counterpart of TestValidateACLRow.
// Plan bindings feed the CFK YAML emitter, the mds-curl HTTP body emitter,
// and the apply path's POST body — a '\n' or '\x00' would inject sibling
// YAML keys, break HTTP headers, or escape a shell comment depending on the
// consumer. ValidatePlan rejects them at WritePlan / ReadPlan time so the
// downstream emitters can trust their inputs.
func TestValidatePlan(t *testing.T) {
	cleanBinding := types.Binding{
		ID: "rb-aaaa", Action: types.ActionCreate, Principal: "User:alice",
		Role: "DeveloperRead", Scope: types.Scope{KafkaCluster: "lkc-1"},
		ResourcePatterns: []types.ResourcePattern{
			{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral},
		},
		SourceACLIDs: []int{1},
	}

	if err := types.ValidatePlan(types.Plan{Bindings: []types.Binding{cleanBinding}}); err != nil {
		t.Fatalf("clean plan should validate: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(b *types.Binding)
		want   string // substring
	}{
		{"principal-newline", func(b *types.Binding) { b.Principal = "User:eve\nrm -rf /" }, "principal"},
		{"role-tab", func(b *types.Binding) { b.Role = "Developer\tRead" }, "role"},
		{"kafka-cluster-null", func(b *types.Binding) { b.Scope.KafkaCluster = "lkc-1\x00" }, "kafka_cluster"},
		{"environment-cr", func(b *types.Binding) { b.Scope.Environment = "env-1\r" }, "environment"},
		{"resource-pattern-name-newline", func(b *types.Binding) {
			b.ResourcePatterns = []types.ResourcePattern{
				{ResourceType: types.ResourceTopic, Name: "topic\necho pwned", PatternType: types.PatternLiteral},
			}
		}, "resource_patterns[0].name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := cleanBinding
			tc.mutate(&b)
			err := types.ValidatePlan(types.Plan{Bindings: []types.Binding{b}})
			if err == nil {
				t.Fatalf("expected error mentioning %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should name the offending field %q; got: %v", tc.want, err)
			}
		})
	}
}

// TestValidateACLSet checks the per-set wrapper reports the first failing
// row (so an operator with a tampered acls.json gets a precise acl_id).
func TestValidateACLSet(t *testing.T) {
	set := types.ACLSet{
		SchemaVersion: "1",
		ACLs: []types.ACLRow{
			{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead,
				ResourceType: types.ResourceTopic, ResourceName: "ok",
				PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
			{ID: 42, Principal: "User:eve\nrm -rf /", Host: "*", Operation: types.OpRead,
				ResourceType: types.ResourceTopic, ResourceName: "secrets",
				PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny},
		},
	}
	err := types.ValidateACLSet(set)
	if err == nil {
		t.Fatal("expected error on the tampered second row")
	}
	if !strings.Contains(err.Error(), "acl_id=42") {
		t.Errorf("error should pinpoint the failing acl_id=42; got: %v", err)
	}
}
