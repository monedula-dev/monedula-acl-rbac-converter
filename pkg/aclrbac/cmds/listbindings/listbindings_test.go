// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package listbindings_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/listbindings"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// kafkaScope is the lookup scope used by every test; the real MDS rolebindings
// lookup is per-principal at a concrete scope.
var kafkaScope = types.Scope{KafkaCluster: "lkc-kafka01"}

// aliceRolebindings is the real MDS response shape: rolebindings keyed by
// principal then role.
const aliceRolebindings = `{"scope":{"clusters":{"kafka-cluster":"lkc-kafka01"}},` +
	`"rolebindings":{"User:alice":{"DeveloperRead":[{"resourceType":"Topic","name":"orders","patternType":"LITERAL"}]}}}`

func listBindingsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(aliceRolebindings))
	}
}

func TestRun_FiltersByPrincipal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "User:alice") {
			t.Errorf("expected principal in path: %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(aliceRolebindings))
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	var buf bytes.Buffer
	err := listbindings.Run(&buf, listbindings.Options{
		Client:          cl,
		PrincipalFilter: []string{"User:alice"},
		Scope:           kafkaScope,
		Format:          listbindings.FormatText,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(buf.String(), "DeveloperRead") {
		t.Errorf("output missing DeveloperRead:\n%s", buf.String())
	}
}

func TestRun_JSONFormat_HasSchemaVersionEnvelope(t *testing.T) {
	srv := httptest.NewServer(listBindingsHandler())
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	var buf bytes.Buffer
	if err := listbindings.Run(&buf, listbindings.Options{
		Client: cl, PrincipalFilter: []string{"User:alice"}, Scope: kafkaScope, Format: listbindings.FormatJSON,
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	var got listbindings.Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	if got.SchemaVersion != "1" {
		t.Errorf("schema_version: got %q", got.SchemaVersion)
	}
	if len(got.Bindings) != 1 || got.Bindings[0].Role != "DeveloperRead" {
		t.Errorf("bindings: got %+v", got.Bindings)
	}
}

func TestRun_YAMLFormat_HasSchemaVersionEnvelope(t *testing.T) {
	srv := httptest.NewServer(listBindingsHandler())
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	var buf bytes.Buffer
	if err := listbindings.Run(&buf, listbindings.Options{
		Client: cl, PrincipalFilter: []string{"User:alice"}, Scope: kafkaScope, Format: listbindings.FormatYAML,
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	var got listbindings.Report
	if err := yaml.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	if got.SchemaVersion != "1" || len(got.Bindings) != 1 {
		t.Errorf("envelope: %+v", got)
	}
}

func TestRun_JSONFormat_NoBindings_EmitsEmptyArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rolebindings":{}}`))
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	var buf bytes.Buffer
	if err := listbindings.Run(&buf, listbindings.Options{
		Client: cl, PrincipalFilter: []string{"User:alice"}, Scope: kafkaScope, Format: listbindings.FormatJSON,
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(buf.String(), `"bindings": []`) {
		t.Errorf("empty bindings should marshal as `[]` not `null`:\n%s", buf.String())
	}
}

// TestRun_NoPrincipalFilterErrors pins that listing requires a principal
// filter: MDS has no all-principals rolebindings endpoint.
func TestRun_NoPrincipalFilterErrors(t *testing.T) {
	cl, _ := mds.NewClient(mds.Config{URL: "http://unused", Token: "t"})
	var buf bytes.Buffer
	if err := listbindings.Run(&buf, listbindings.Options{Client: cl, Scope: kafkaScope, Format: listbindings.FormatJSON}); err == nil {
		t.Fatal("expected an error when no principal filter is given")
	}
}

// TestRun_NoScopeErrors pins that a lookup scope is required.
func TestRun_NoScopeErrors(t *testing.T) {
	cl, _ := mds.NewClient(mds.Config{URL: "http://unused", Token: "t"})
	var buf bytes.Buffer
	if err := listbindings.Run(&buf, listbindings.Options{Client: cl, PrincipalFilter: []string{"User:alice"}, Format: listbindings.FormatJSON}); err == nil {
		t.Fatal("expected an error when no scope is given")
	}
}

func TestRun_MultiplePrincipalFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "User:alice"):
			_, _ = w.Write([]byte(aliceRolebindings))
		case strings.Contains(r.URL.Path, "User:bob"):
			_, _ = w.Write([]byte(`{"rolebindings":{"User:bob":{"ResourceOwner":[]}}}`))
		default:
			_, _ = w.Write([]byte(`{"rolebindings":{}}`))
		}
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	var buf bytes.Buffer
	if err := listbindings.Run(&buf, listbindings.Options{
		Client: cl, PrincipalFilter: []string{"User:alice", "User:bob"}, Scope: kafkaScope, Format: listbindings.FormatJSON,
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	var got listbindings.Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Bindings) != 2 {
		t.Errorf("want 2 concatenated bindings, got %d: %+v", len(got.Bindings), got.Bindings)
	}
}

func TestRun_TextFormat_Default(t *testing.T) {
	srv := httptest.NewServer(listBindingsHandler())
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	var buf bytes.Buffer
	if err := listbindings.Run(&buf, listbindings.Options{
		Client: cl, PrincipalFilter: []string{"User:alice"}, Scope: kafkaScope,
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	line := buf.String()
	if !strings.Contains(line, "User:alice") || !strings.Contains(line, "DeveloperRead") {
		t.Errorf("text output missing principal/role:\n%s", line)
	}
	if !strings.Contains(line, "\t") {
		t.Errorf("text output should be tab-separated:\n%q", line)
	}
}

func TestRun_MDSError_Propagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t", MaxRetries: 0})
	var buf bytes.Buffer
	err := listbindings.Run(&buf, listbindings.Options{
		Client: cl, PrincipalFilter: []string{"User:alice"}, Scope: kafkaScope, Format: listbindings.FormatJSON,
	})
	if err == nil {
		t.Fatal("expected an error when MDS returns 500")
	}
}
