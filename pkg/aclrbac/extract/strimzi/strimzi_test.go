// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package strimzi_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/strimzi"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestExtract_KafkaUser(t *testing.T) {
	a, _ := strimzi.New("testdata/basic-user.yaml")
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 3 {
		t.Errorf("got %d ACLs, want 3", len(set.ACLs))
	}
	if set.ACLs[0].Principal != "User:alice" {
		t.Errorf("principal: %q", set.ACLs[0].Principal)
	}
	if set.ACLs[0].ResourceType != types.ResourceTopic {
		t.Errorf("resource type: %q", set.ACLs[0].ResourceType)
	}
}

// TestParseStream_PrefixPatternMapsToPREFIXED pins that Strimzi's
// `patternType: prefix` maps to the canonical IR value PREFIXED. The old code
// uppercased it to the invalid "PREFIX".
func TestParseStream_PrefixPatternMapsToPREFIXED(t *testing.T) {
	stream := []byte(`apiVersion: kafka.strimzi.io/v1beta2
kind: KafkaUser
metadata:
  name: alice
  namespace: kafka
spec:
  authorization:
    type: simple
    acls:
      - resource: {type: topic, name: app-, patternType: prefix}
        operations: [Read]
        host: "*"
`)
	rows, err := strimzi.ParseStream(stream, extract.NewLogger())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].PatternType != types.PatternPrefixed {
		t.Errorf("patternType: got %q, want PREFIXED", rows[0].PatternType)
	}
}

// TestParseStream_SingularOperationField pins that the deprecated singular
// Strimzi `operation` field is honored. Older KafkaUser manifests use
// `operation: Read` instead of `operations: [Read]`; the old struct only read
// `operations`, so such rules silently produced zero ACLs.
func TestParseStream_SingularOperationField(t *testing.T) {
	stream := []byte(`apiVersion: kafka.strimzi.io/v1beta2
kind: KafkaUser
metadata:
  name: alice
  namespace: kafka
spec:
  authorization:
    type: simple
    acls:
      - resource: {type: topic, name: orders, patternType: literal}
        operation: Read
        host: "*"
`)
	rows, err := strimzi.ParseStream(stream, extract.NewLogger())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 || rows[0].Operation != types.OpRead {
		t.Fatalf("singular operation not honored; got rows=%+v", rows)
	}
}

// TestParseStream_MalformedDocSkipped is the D2 regression guard: a single
// malformed YAML doc in a multi-doc stream must NOT poison every other doc
// (the previous behaviour aborted with `return nil, err`). Mirrors the CFK
// extractor's "log WARN and continue" tolerance.
func TestParseStream_MalformedDocSkipped(t *testing.T) {
	// Three docs: a bad one between two valid ones. The valid docs must
	// produce ACLs.
	stream := []byte(`---
apiVersion: kafka.strimzi.io/v1beta2
kind: KafkaUser
metadata:
  name: alice
  namespace: kafka
spec:
  authorization:
    type: simple
    acls:
      - resource: {type: topic, name: orders, patternType: literal}
        operations: [Read]
        host: "*"
---
this: is: not: valid: yaml: at: all
  -malformed
---
apiVersion: kafka.strimzi.io/v1beta2
kind: KafkaUser
metadata:
  name: bob
  namespace: kafka
spec:
  authorization:
    type: simple
    acls:
      - resource: {type: topic, name: events, patternType: literal}
        operations: [Write]
        host: "*"
`)
	rows, err := strimzi.ParseStream(stream, extract.NewLogger())
	if err != nil {
		t.Fatalf("malformed middle doc must NOT abort the stream; got err: %v", err)
	}
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
