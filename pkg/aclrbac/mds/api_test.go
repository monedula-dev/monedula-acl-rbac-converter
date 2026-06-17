// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestProbeCapability_Modern(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/security/1.0/roles" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`[]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	cap, err := mds.ProbeCapability(cl)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if cap != mds.CapabilityLookup {
		t.Errorf("got %q, want CapabilityLookup", cap)
	}
}

func TestProbeCapability_Legacy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(nil, "", 404)
	}))
	// HandlerFunc above doesn't actually serve; use a simpler one:
	srv.Close()
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	cap, err := mds.ProbeCapability(cl)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if cap != mds.CapabilityLegacy {
		t.Errorf("got %q, want CapabilityLegacy", cap)
	}
}

func TestCreateRoleBinding(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(204)
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	b := types.Binding{
		Principal: "User:alice",
		Role:      "DeveloperRead",
		Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
		}},
	}
	if err := mds.CreateRoleBinding(cl, b); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.Contains(gotPath, "User:alice") {
		t.Errorf("path missing principal: %q", gotPath)
	}
	if !strings.Contains(gotPath, "DeveloperRead") {
		t.Errorf("path missing role: %q", gotPath)
	}
	if !strings.Contains(gotBody, "Topic") {
		t.Errorf("body missing Topic: %q", gotBody)
	}
	// MDS requires camelCase keys; snake_case is rejected (HTTP 400).
	for _, want := range []string{`"resourcePatterns"`, `"resourceType"`, `"patternType"`} {
		if !strings.Contains(gotBody, want) {
			t.Errorf("body must use camelCase key %s; got %q", want, gotBody)
		}
	}
	if strings.Contains(gotBody, "resource_patterns") || strings.Contains(gotBody, "resource_type") {
		t.Errorf("body must not use snake_case keys; got %q", gotBody)
	}
}

// TestCreateRoleBinding_DNPrincipalNotDoubleEscaped pins that a principal
// containing characters PathEscape encodes (comma, space — common in mTLS DNs)
// reaches the server decoded to its original value, i.e. it is percent-encoded
// exactly once on the wire. The old do() assigned the already-escaped path to
// u.Path without setting u.RawPath, so url.URL.String re-escaped the '%',
// turning %2C into %252C and creating a binding for a mangled principal.
func TestCreateRoleBinding_DNPrincipalNotDoubleEscaped(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path // server-decoded once
		w.WriteHeader(204)
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	b := types.Binding{
		Principal: "User:CN=app,OU=x",
		Role:      "DeveloperRead",
		Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
		}},
	}
	if err := mds.CreateRoleBinding(cl, b); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.Contains(gotPath, "User:CN=app,OU=x") {
		t.Errorf("principal was double-escaped on the wire; server saw path %q (want decoded comma)", gotPath)
	}
}

func TestListRoleBindings_FilterByPrincipal(t *testing.T) {
	var gotPath, gotMethod, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		// Real MDS shape: rolebindings keyed by principal then role.
		_, _ = w.Write([]byte(`{"scope":{"clusters":{"kafka-cluster":"lkc-kafka01"}},` +
			`"rolebindings":{"User:alice":{"DeveloperRead":[{"resourceType":"Topic","name":"orders","patternType":"LITERAL"}]}}}`))
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	got, err := mds.ListBindings(cl, "User:alice", types.Scope{KafkaCluster: "lkc-kafka01"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method: got %s, want POST", gotMethod)
	}
	if gotPath != "/security/1.0/lookup/rolebindings/principal/User:alice" {
		t.Errorf("path: got %q", gotPath)
	}
	if !strings.Contains(gotBody, `"kafka-cluster":"lkc-kafka01"`) {
		t.Errorf("body should carry the scope; got %q", gotBody)
	}
	if len(got) != 1 {
		t.Fatalf("got %d bindings, want 1", len(got))
	}
	if got[0].Role != "DeveloperRead" || got[0].Scope.KafkaCluster != "lkc-kafka01" {
		t.Errorf("binding: %+v", got[0])
	}
	if len(got[0].ResourcePatterns) != 1 || got[0].ResourcePatterns[0].Name != "orders" {
		t.Errorf("patterns: %+v", got[0].ResourcePatterns)
	}
}

var effScope = types.Scope{KafkaCluster: "lkc-kafka01"}

// effectiveFake serves the two real MDS endpoints LookupAllowed uses: the
// POST principal-resources lookup (role -> resource patterns) and the GET role
// definition (resourceType -> operations). patternsJSON is the role-pattern
// map body; the DeveloperRead role grants Read+Describe on Topic.
func effectiveFake(patternsJSON string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/security/1.0/roles/"):
			_, _ = w.Write([]byte(`{"name":"DeveloperRead","accessPolicy":{"allowedOperations":[{"resourceType":"Topic","operations":["Read","Describe"]}]}}`))
		case strings.HasSuffix(r.URL.Path, "/resources"):
			_, _ = w.Write([]byte(patternsJSON))
		default:
			http.NotFound(w, r)
		}
	}
}

func TestLookupEffective(t *testing.T) {
	srv := httptest.NewServer(effectiveFake(
		`{"User:alice":{"DeveloperRead":[{"resourceType":"Topic","name":"orders","patternType":"LITERAL"}]}}`))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	allowed, err := mds.LookupAllowed(cl, "User:alice", types.OpRead, types.ResourceTopic, "orders", types.PatternLiteral, effScope)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !allowed {
		t.Error("LookupAllowed should return true for matched tuple")
	}
}

// TestLookupEffective_PrefixedMatchRequiresPrefix pins the spec §11.2
// resource-name rule for PREFIXED bindings: the binding's prefix must
// be a prefix of the queried name. Without this check (the pre-fix
// behaviour), a PREFIXED binding for "orders." would falsely vouch
// for a queried prefix "payments." simply because both rows had the
// same type / op / pattern type.
func TestLookupEffective_PrefixedMatchRequiresPrefix(t *testing.T) {
	srv := httptest.NewServer(effectiveFake(
		`{"User:alice":{"DeveloperRead":[{"resourceType":"Topic","name":"orders.","patternType":"PREFIXED"}]}}`))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})

	// PREFIXED binding "orders." vouches for query prefix "orders." itself.
	if allowed, err := mds.LookupAllowed(cl, "User:alice", types.OpRead, types.ResourceTopic, "orders.", types.PatternPrefixed, effScope); err != nil {
		t.Fatalf("lookup orders.: %v", err)
	} else if !allowed {
		t.Error("PREFIXED binding 'orders.' should cover query prefix 'orders.'")
	}

	// PREFIXED binding "orders." vouches for query prefix "orders.processed"
	// because "orders." is a prefix of "orders.processed".
	if allowed, err := mds.LookupAllowed(cl, "User:alice", types.OpRead, types.ResourceTopic, "orders.processed", types.PatternPrefixed, effScope); err != nil {
		t.Fatalf("lookup orders.processed: %v", err)
	} else if !allowed {
		t.Error("PREFIXED binding 'orders.' should cover narrower query prefix 'orders.processed'")
	}

	// PREFIXED binding "orders." must NOT vouch for query prefix
	// "payments.". This is the regression.
	if allowed, err := mds.LookupAllowed(cl, "User:alice", types.OpRead, types.ResourceTopic, "payments.", types.PatternPrefixed, effScope); err != nil {
		t.Fatalf("lookup payments.: %v", err)
	} else if allowed {
		t.Error("PREFIXED binding 'orders.' must not cover unrelated query prefix 'payments.'")
	}
}

// TestLookupEffective_LiteralMatchRequiresExactName guards the
// literal-name equality contract — already in place before the fix
// but pinned here so the new pattern-type switch can't accidentally
// loosen it.
func TestLookupEffective_LiteralMatchRequiresExactName(t *testing.T) {
	srv := httptest.NewServer(effectiveFake(
		`{"User:alice":{"DeveloperRead":[{"resourceType":"Topic","name":"orders","patternType":"LITERAL"}]}}`))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	if allowed, err := mds.LookupAllowed(cl, "User:alice", types.OpRead, types.ResourceTopic, "orders.processed", types.PatternLiteral, effScope); err != nil {
		t.Fatalf("lookup: %v", err)
	} else if allowed {
		t.Error("LITERAL binding 'orders' must not cover literal query 'orders.processed'")
	}
}
