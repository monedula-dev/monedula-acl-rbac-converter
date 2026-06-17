// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cfk_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/cfk"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestExtract_CFKDir(t *testing.T) {
	a, _ := cfk.New("testdata/basic")
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	// 2 superusers in Kafka CR -> 2 ALL-on-Cluster ACL rows.
	if len(set.ACLs) != 2 {
		t.Errorf("got %d ACLs, want 2", len(set.ACLs))
	}
	for _, r := range set.ACLs {
		if r.ResourceType != types.ResourceCluster || r.Operation != types.OpAll {
			t.Errorf("superuser row should be ALL on Cluster; got %+v", r)
		}
	}
}

// TestParseStream_RolebindingRealCRDShape pins that ConfluentRolebinding CRs
// are parsed using the REAL CFK CRD schema: cluster scope is expressed via
// spec.clustersScopeByIds.kafkaClusterId (the nonexistent spec.kafkaClusterRef
// the code used to read meant every real CR was dropped, so the inventory was
// always empty against a real cluster).
func TestParseStream_RolebindingRealCRDShape(t *testing.T) {
	stream := []byte(`apiVersion: platform.confluent.io/v1beta1
kind: ConfluentRolebinding
metadata:
  name: rb-existing-001
spec:
  principal:
    type: user
    name: alice@acme.com
  role: DeveloperRead
  resourcePatterns:
    - resourceType: Topic
      name: orders
      patternType: LITERAL
  clustersScopeByIds:
    kafkaClusterId: lkc-abc123
`)
	_, bindings, _ := cfk.ParseStream(stream, 1, extract.NewLogger())
	if len(bindings) != 1 {
		t.Fatalf("got %d bindings, want 1 (real-CRD ConfluentRolebinding must be inventoried)", len(bindings))
	}
	b := bindings[0]
	if b.Principal != "User:alice@acme.com" {
		t.Errorf("principal: got %q", b.Principal)
	}
	if b.Role != "DeveloperRead" {
		t.Errorf("role: got %q", b.Role)
	}
	if b.Scope.KafkaCluster != "lkc-abc123" {
		t.Errorf("scope.KafkaCluster: got %q, want lkc-abc123", b.Scope.KafkaCluster)
	}
	if len(b.ResourcePatterns) != 1 || b.ResourcePatterns[0].Name != "orders" {
		t.Errorf("resourcePatterns: got %+v", b.ResourcePatterns)
	}
}

// TestParseStream_MalformedDocSkipped is the D2-mirror regression guard for
// CFK: a single malformed YAML doc in a multi-doc stream must NOT poison
// every other doc (CFK already logs WARN and continues; this locks that in
// against future regressions). The strimzi extractor was hardened to match.
func TestParseStream_MalformedDocSkipped(t *testing.T) {
	stream := []byte(`---
apiVersion: platform.confluent.io/v1beta1
kind: Kafka
metadata:
  name: kafka-a
  namespace: confluent
spec:
  authorization:
    type: simple
    superUsers:
      - User:alice
---
this: is: not: valid: yaml: at: all
  -malformed
---
apiVersion: platform.confluent.io/v1beta1
kind: Kafka
metadata:
  name: kafka-b
  namespace: confluent
spec:
  authorization:
    type: simple
    superUsers:
      - User:bob
`)
	rows, _, _ := cfk.ParseStream(stream, 1, extract.NewLogger())
	gotPrincipals := map[string]bool{}
	for _, r := range rows {
		gotPrincipals[r.Principal] = true
	}
	for _, want := range []string{"User:alice", "User:bob"} {
		if !gotPrincipals[want] {
			t.Errorf("expected ACLs for %s after skipping the malformed middle doc; got %d rows total", want, len(rows))
		}
	}
}

// The existing-bindings.json contract (shape + SKIP_EXISTS behaviour +
// absent/malformed handling) is covered end-to-end through the real `plan`
// command in cli/plan_existing_test.go, which exercises the consumer that's
// actually used. The previously-here cfk.ReadExistingBindings was an unused
// exported duplicate of that consumer and was removed.
