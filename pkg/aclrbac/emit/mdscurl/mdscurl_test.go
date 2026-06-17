// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mdscurl_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/mdscurl"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestEmit_Basic(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
		Principal: "User:alice", Role: "DeveloperRead",
		Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
		}},
		SourceACLIDs: []int{1, 2},
	}}}

	var buf bytes.Buffer
	em := mdscurl.New(mdscurl.Options{PlanPath: "test.json"})
	n, err := em.Emit(&buf, plan)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("created count: got %d, want 1", n)
	}
	out := buf.String()
	for _, want := range []string{
		"#!/usr/bin/env bash",
		"MDS_URL",
		"MDS_TOKEN",
		"curl -fsS -X POST",
		"Authorization: Bearer",
		"User:alice/roles/DeveloperRead/bindings",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestEmit_CamelCaseBody pins that the request body uses the camelCase keys
// the real MDS REST API requires (resourcePatterns/resourceType/patternType).
// Verified empirically: snake_case keys are rejected by MDS with HTTP 400.
func TestEmit_CamelCaseBody(t *testing.T) {
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
		Principal: "User:alice", Role: "DeveloperRead",
		Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
		}},
	}}}
	var buf bytes.Buffer
	if _, err := mdscurl.New(mdscurl.Options{}).Emit(&buf, plan); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`"resourcePatterns"`, `"resourceType"`, `"patternType"`} {
		if !strings.Contains(out, want) {
			t.Errorf("body must use camelCase key %s; output:\n%s", want, out)
		}
	}
	for _, bad := range []string{`"resource_patterns"`, `"resource_type"`, `"pattern_type"`} {
		if strings.Contains(out, bad) {
			t.Errorf("body must NOT use snake_case key %s (MDS rejects it)", bad)
		}
	}
}

// TestEmit_PrincipalShellSafe pins both halves of the script-safety
// contract: tricky principals/roles get URL-escaped (so the request
// line isn't corrupted) AND the four bash-double-quote interpolation
// characters '$', '`', '"', '\\' are percent-encoded (so the
// generated `"${MDS_URL}/.../<principal>/..."` cannot trigger shell
// expansion when the operator runs the script). Regression: pre-fix
// the principal embedded raw into the URL.
func TestEmit_PrincipalShellSafe(t *testing.T) {
	// Pick a principal that exercises every channel:
	//   $HOME      - shell variable expansion
	//   `id`       - command substitution
	//   "          - closes the surrounding double-quoted URL
	//   \          - bash escape character
	//   /          - URL path separator (must not split the segment)
	//   ?          - would otherwise terminate the URL path
	naughty := `User:alice$HOME` + "`id`" + `"\\/?evil`
	plan := types.Plan{Bindings: []types.Binding{{
		ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
		Principal: naughty, Role: "DeveloperRead",
		Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
		}},
		SourceACLIDs: []int{1},
	}}}

	var buf bytes.Buffer
	if _, err := mdscurl.New(mdscurl.Options{}).Emit(&buf, plan); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// None of the dangerous raw bytes may survive into the script.
	// (We check for the substring as it would appear inside the URL:
	// without these escapes, '$HOME' would be substituted at run time.)
	for _, banned := range []string{
		"$HOME",
		"`id`",
		`"\\`, // backslash inside the URL would consume the trailing quote
		`"\`,
	} {
		if strings.Contains(out, banned) {
			t.Errorf("output contains raw %q — bash will interpolate it:\n%s", banned, out)
		}
	}

	// Positive checks for the escaped forms.
	for _, want := range []string{
		"%24HOME",  // $
		"%60id%60", // backticks
		"%22",      // double-quote
		"%5C",      // backslash
		"%2F",      // /
		"%3F",      // ?
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected escaped %q in output:\n%s", want, out)
		}
	}
}
