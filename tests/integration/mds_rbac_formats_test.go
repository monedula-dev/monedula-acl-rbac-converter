// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/monedula-dev/monedula-acl-rbac-converter/internal/mdstest"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// aclRow is one logical ACL in the shared "complex" fixture. The same set is
// encoded into every input format so the conversion-to-RBAC result is
// comparable across formats.
type aclRow struct {
	principal string // e.g. "User:alice"
	op        string // canonical IR op: Read, Write, Describe, All
	rtype     string // Topic | Group
	rname     string
	pattern   string // LITERAL | PREFIXED
	deny      bool
}

// complexACLs is a deliberately rich set: multiple principals, Topic and Group
// resources, LITERAL and PREFIXED patterns, an ALL grant, and a DENY (which
// converts to a rejected entry, not a binding). The ALLOW rows yield 5 role
// bindings:
//
//	User:alice  DeveloperRead  Topic:orders   (Read+Describe)
//	User:bob    DeveloperWrite Topic:payments (Write+Describe)
//	User:carol  DeveloperRead  Topic:events-* (Read+Describe, PREFIXED)
//	User:frank  DeveloperRead  Group:app-consumers (Read+Describe)
//	User:dave   ResourceOwner  Topic:admin    (All)
var complexACLs = []aclRow{
	{principal: "User:alice", op: "Read", rtype: "Topic", rname: "orders", pattern: "LITERAL"},
	{principal: "User:alice", op: "Describe", rtype: "Topic", rname: "orders", pattern: "LITERAL"},
	{principal: "User:bob", op: "Write", rtype: "Topic", rname: "payments", pattern: "LITERAL"},
	{principal: "User:bob", op: "Describe", rtype: "Topic", rname: "payments", pattern: "LITERAL"},
	{principal: "User:carol", op: "Read", rtype: "Topic", rname: "events-", pattern: "PREFIXED"},
	{principal: "User:carol", op: "Describe", rtype: "Topic", rname: "events-", pattern: "PREFIXED"},
	{principal: "User:frank", op: "Read", rtype: "Group", rname: "app-consumers", pattern: "LITERAL"},
	{principal: "User:frank", op: "Describe", rtype: "Group", rname: "app-consumers", pattern: "LITERAL"},
	{principal: "User:dave", op: "All", rtype: "Topic", rname: "admin", pattern: "LITERAL"},
	{principal: "User:eve", op: "Read", rtype: "Topic", rname: "secrets", pattern: "LITERAL", deny: true},
}

const wantBindings = 5 // ALLOW-derived role bindings the plan must produce

// ---- per-format encoders -----------------------------------------------------

func encodeJSON(t *testing.T, rows []aclRow) []byte {
	t.Helper()
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
	}
	for i, r := range rows {
		perm := types.PermissionAllow
		if r.deny {
			perm = types.PermissionDeny
		}
		set.ACLs = append(set.ACLs, types.ACLRow{
			ID: i + 1, Principal: r.principal, Host: "*",
			Operation: types.Operation(r.op), ResourceType: types.ResourceType(r.rtype),
			ResourceName: r.rname, PatternType: types.PatternType(r.pattern), PermissionType: perm,
		})
	}
	b, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func encodeYAML(t *testing.T, rows []aclRow) []byte {
	t.Helper()
	// Reuse the JSON IR then re-marshal as YAML via a generic decode so the
	// keys stay the snake_case the yaml adapter expects.
	var generic map[string]interface{}
	if err := json.Unmarshal(encodeJSON(t, rows), &generic); err != nil {
		t.Fatal(err)
	}
	b, err := yaml.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func encodeCSV(_ *testing.T, rows []aclRow) []byte {
	var b strings.Builder
	b.WriteString("id,principal,host,operation,resource_type,resource_name,pattern_type,permission_type\n")
	for i, r := range rows {
		perm := "Allow"
		if r.deny {
			perm = "Deny"
		}
		fmt.Fprintf(&b, "%d,%s,*,%s,%s,%s,%s,%s\n", i+1, r.principal, r.op, r.rtype, r.rname, r.pattern, perm)
	}
	return []byte(b.String())
}

func encodeText(_ *testing.T, rows []aclRow) []byte {
	// Group by (resourceType, name, patternType) and emit kafka-acls --list blocks.
	type key struct{ rt, name, pat string }
	order := []key{}
	byRes := map[key][]aclRow{}
	for _, r := range rows {
		k := key{r.rtype, r.rname, r.pattern}
		if _, ok := byRes[k]; !ok {
			order = append(order, k)
		}
		byRes[k] = append(byRes[k], r)
	}
	var b strings.Builder
	for _, k := range order {
		fmt.Fprintf(&b, "Current ACLs for resource `ResourcePattern(resourceType=%s, name=%s, patternType=%s)`:\n",
			strings.ToUpper(k.rt), k.name, strings.ToUpper(k.pat))
		for _, r := range byRes[k] {
			perm := "ALLOW"
			if r.deny {
				perm = "DENY"
			}
			fmt.Fprintf(&b, "\t(principal=%s, host=*, operation=%s, permissionType=%s)\n",
				r.principal, strings.ToUpper(r.op), perm)
		}
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func encodeStrimzi(_ *testing.T, rows []aclRow) []byte {
	// One KafkaUser per principal.
	order := []string{}
	byPrincipal := map[string][]aclRow{}
	for _, r := range rows {
		if _, ok := byPrincipal[r.principal]; !ok {
			order = append(order, r.principal)
		}
		byPrincipal[r.principal] = append(byPrincipal[r.principal], r)
	}
	var b strings.Builder
	for i, p := range order {
		if i > 0 {
			b.WriteString("---\n")
		}
		name := strings.TrimPrefix(p, "User:")
		b.WriteString("apiVersion: kafka.strimzi.io/v1beta2\n")
		b.WriteString("kind: KafkaUser\n")
		fmt.Fprintf(&b, "metadata:\n  name: %s\n  namespace: kafka\n", name)
		b.WriteString("spec:\n  authorization:\n    type: simple\n    acls:\n")
		for _, r := range byPrincipal[p] {
			typ := "allow"
			if r.deny {
				typ = "deny"
			}
			// Strimzi's resource.patternType enum is literal|prefix (NOT
			// "prefixed" — that's the IR value).
			szPat := "literal"
			if r.pattern == "PREFIXED" {
				szPat = "prefix"
			}
			fmt.Fprintf(&b, "      - resource: {type: %s, name: %s, patternType: %s}\n",
				strings.ToLower(r.rtype), r.rname, szPat)
			fmt.Fprintf(&b, "        operations: [%s]\n        host: \"*\"\n        type: %s\n", r.op, typ)
		}
	}
	return []byte(b.String())
}

func encodeScript(_ *testing.T, rows []aclRow) []byte {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	for _, r := range rows {
		principalFlag := "--allow-principal"
		if r.deny {
			principalFlag = "--deny-principal"
		}
		resFlag := "--topic"
		if r.rtype == "Group" {
			resFlag = "--group"
		}
		fmt.Fprintf(&b, "kafka-acls --bootstrap-server localhost:9092 --add %s %s --operation %s %s %s --resource-pattern-type %s\n",
			principalFlag, r.principal, r.op, resFlag, r.rname, strings.ToLower(r.pattern))
	}
	return []byte(b.String())
}

// formatCase pairs an input-format name with the file it produces.
type formatCase struct {
	from   string // --from value
	file   string // fixture filename
	encode func(*testing.T, []aclRow) []byte
}

var formatCases = []formatCase{
	{from: "json", file: "acls.json", encode: encodeJSON},
	{from: "yaml", file: "acls.yaml", encode: encodeYAML},
	{from: "csv", file: "acls.csv", encode: encodeCSV},
	{from: "text", file: "acls.txt", encode: encodeText},
	{from: "strimzi", file: "users.yaml", encode: encodeStrimzi},
	{from: "script", file: "setup-acls.sh", encode: encodeScript},
}

// TestRealMDS_ConvertAllFormats runs the full conversion pipeline — extract →
// plan → apply → verify — against a real MDS, once per input format, on every
// CP version. Each format encodes the same complex ACL set, so the run proves
// that adapter parses real-world input AND that the resulting RBAC bindings
// actually round-trip through MDS.
func TestRealMDS_ConvertAllFormats(t *testing.T) {
	for _, spec := range mdstest.CPSpecs {
		t.Run(spec.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			stack, terminate := mdstest.StartMDSStack(ctx, t, spec)
			defer terminate()
			t.Logf("%s MDS up at %s (cluster %s)", spec.Name, stack.URL, stack.ClusterID)

			for _, fc := range formatCases {
				t.Run(fc.from, func(t *testing.T) {
					runConversion(t, stack, fc)
				})
			}
		})
	}
}

func runConversion(t *testing.T, stack mdstest.Stack, fc formatCase) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, fc.file)
	if err := os.WriteFile(inputPath, fc.encode(t, complexACLs), 0o644); err != nil {
		t.Fatal(err)
	}
	aclsPath := filepath.Join(dir, "acls.json")
	scopesPath := filepath.Join(dir, "scopes.yaml")
	planPath := filepath.Join(dir, "plan.json")
	verifyPath := filepath.Join(dir, "verify.json")
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: "+stack.ClusterID+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// extract
	if exit := cli.Execute([]string{"extract", "--from", fc.from, "--input", inputPath, "--out", aclsPath}); exit != 0 {
		t.Fatalf("[%s] extract exit %d", fc.from, exit)
	}
	// plan (--allow-rejected: the fixture intentionally includes a DENY, which
	// converts to a rejected entry rather than a binding).
	if exit := cli.Execute([]string{"plan", "--acls", aclsPath, "--scopes", scopesPath, "--out", planPath, "--allow-rejected"}); exit != 0 {
		t.Fatalf("[%s] plan exit %d", fc.from, exit)
	}
	if got := planBindingCount(t, planPath); got != wantBindings {
		t.Fatalf("[%s] plan produced %d bindings, want %d", fc.from, got, wantBindings)
	}
	// apply (real MDS)
	mdsArgs := []string{"--mds-url", stack.URL, "--mds-user", "mds", "--mds-password-file", stack.PWFile}
	if exit := cli.Execute(append([]string{"apply", "--plan", planPath, "--confirm"}, mdsArgs...)); exit != 0 {
		t.Fatalf("[%s] apply exit %d", fc.from, exit)
	}
	// Verify the bindings actually exist in MDS (the conversion landed). MDS's
	// rolebindings lookup is eventually consistent — it serves from a metadata
	// cache that lags the create — so retry until healthy rather than asserting
	// on a single possibly-stale read. verify.json is rewritten each run.
	verifyArgs := append([]string{"verify", "--plan", planPath, "--mode", "bindings-exist", "--out", verifyPath}, mdsArgs...)
	deadline := time.Now().Add(20 * time.Second)
	for {
		cli.Execute(verifyArgs)
		if bindingsAllExist(verifyPath) || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	assertAllBindingsExist(t, fc.from, planPath, verifyPath, stack)
}

func planBindingCount(t *testing.T, planPath string) int {
	t.Helper()
	data, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Bindings []json.RawMessage `json:"bindings"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	return len(p.Bindings)
}

// bindingsAllExist reports whether verify.json shows every binding present and
// none missing/unknown — the poll predicate for MDS eventual consistency.
func bindingsAllExist(verifyPath string) bool {
	data, err := os.ReadFile(verifyPath)
	if err != nil {
		return false
	}
	var v struct {
		Counts struct {
			BindingExists  int `json:"binding_exists"`
			BindingMissing int `json:"binding_missing"`
			BindingUnknown int `json:"binding_unknown"`
		} `json:"counts"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return false
	}
	return v.Counts.BindingExists == wantBindings && v.Counts.BindingMissing == 0 && v.Counts.BindingUnknown == 0
}

func assertAllBindingsExist(t *testing.T, format, planPath, verifyPath string, stack mdstest.Stack) {
	t.Helper()
	// Map binding_id -> human description from the plan, so a MISSING result
	// names the principal/role/patterns rather than an opaque id.
	planData, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("[%s] read plan.json: %v", format, err)
	}
	var pl struct {
		Bindings []struct {
			ID               string `json:"id"`
			Principal        string `json:"principal"`
			Role             string `json:"role"`
			ResourcePatterns []struct {
				ResourceType string `json:"resource_type"`
				Name         string `json:"name"`
				PatternType  string `json:"pattern_type"`
			} `json:"resource_patterns"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(planData, &pl); err != nil {
		t.Fatalf("[%s] decode plan.json: %v", format, err)
	}
	desc := map[string]string{}
	idPrincipal := map[string]string{}
	for _, b := range pl.Bindings {
		p := ""
		for _, rp := range b.ResourcePatterns {
			p += fmt.Sprintf("[%s:%s/%s]", rp.ResourceType, rp.Name, rp.PatternType)
		}
		desc[b.ID] = fmt.Sprintf("%s %s %s", b.Principal, b.Role, p)
		idPrincipal[b.ID] = b.Principal
	}

	data, err := os.ReadFile(verifyPath)
	if err != nil {
		t.Fatalf("[%s] read verify.json: %v", format, err)
	}
	var v struct {
		Results []struct {
			BindingID string `json:"binding_id"`
			Status    string `json:"status"`
			Detail    string `json:"detail"`
		} `json:"results"`
		Counts struct {
			BindingExists  int `json:"binding_exists"`
			BindingMissing int `json:"binding_missing"`
			BindingUnknown int `json:"binding_unknown"`
		} `json:"counts"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("[%s] decode verify.json: %v\n%s", format, err, data)
	}
	if v.Counts.BindingExists != wantBindings || v.Counts.BindingMissing != 0 || v.Counts.BindingUnknown != 0 {
		var bad []string
		for _, r := range v.Results {
			if r.Status != "BINDING_EXISTS" {
				bad = append(bad, fmt.Sprintf("%s=%s {%s} %s", r.Status, r.BindingID, desc[r.BindingID], r.Detail))
				// Dump what MDS actually holds for this principal, to tell a
				// content mismatch apart from eventual-consistency lag.
				if p := idPrincipal[r.BindingID]; p != "" {
					tok, _ := mds.ResolveToken(mds.AuthConfig{URL: stack.URL, User: "mds", PasswordFile: stack.PWFile})
					cl, _ := mds.NewClient(mds.Config{URL: stack.URL, Token: tok.Token})
					got, lerr := mds.ListBindings(cl, p, types.Scope{KafkaCluster: stack.ClusterID})
					t.Logf("[%s] MDS actually holds for %s (err=%v): %+v", format, p, lerr, got)
				}
			}
		}
		sort.Strings(bad)
		t.Fatalf("[%s] bindings not confirmed in MDS: exists=%d missing=%d unknown=%d (want exists=%d); not-exists:\n  %s",
			format, v.Counts.BindingExists, v.Counts.BindingMissing, v.Counts.BindingUnknown, wantBindings, strings.Join(bad, "\n  "))
	}
}
