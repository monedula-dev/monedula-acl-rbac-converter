// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package discover_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/discover"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"gopkg.in/yaml.v3"
)

func TestRun_EmitsScopesStub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"kafka_clusters":[{"id":"lkc-kafka01"}]}`))
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	var buf bytes.Buffer
	if err := discover.Run(&buf, cl); err != nil {
		t.Fatalf("run: %v", err)
	}
	out := buf.String()
	// Cluster IDs are emitted as %q-quoted YAML scalars (defensive against
	// MDS payloads with YAML-special chars) — see writeStub.
	if !strings.Contains(out, `kafka_cluster: "lkc-kafka01"`) {
		t.Errorf("output missing kafka_cluster:\n%s", out)
	}
	for _, want := range []string{"# required", "schema_registry_cluster:", "ksql_cluster:", "connect_cluster:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestDiscover_EmptyKafkaList_EmitsValidYAML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"kafka_clusters":[],"schema_registry_clusters":[],"ksql_clusters":[],"connect_clusters":[]}`)
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	var buf bytes.Buffer
	if err := discover.Run(&buf, cl); err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("emitted YAML does not parse: %v\n---\n%s", err, buf.String())
	}
	if v, ok := parsed["kafka_cluster"]; ok && v != "" {
		t.Errorf("kafka_cluster should be empty string when MDS returned no clusters; got %T %v", v, v)
	}
}
