// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package script

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func opsOn(rows []types.ACLRow, rt types.ResourceType, name string) map[types.Operation]bool {
	out := map[types.Operation]bool{}
	for _, r := range rows {
		if r.ResourceType == rt && r.ResourceName == name {
			out[r.Operation] = true
		}
	}
	return out
}

// TestExpand_AllowHostPreserved pins that --allow-host is parsed and applied
// to the emitted rows. Previously every row hardcoded host "*", silently
// broadening a host-restricted grant to all hosts.
func TestExpand_AllowHostPreserved(t *testing.T) {
	p, err := parseInvocation([]string{"kafka-acls", "--add", "--topic", "orders", "--operation", "Read", "--allow-principal", "User:alice", "--allow-host", "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := expand(p, 1, extract.NewLogger())
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].Host != "10.0.0.1" {
		t.Errorf("host: got %q, want 10.0.0.1 (--allow-host must be honored)", rows[0].Host)
	}
}

// TestExpand_DenyHostPreserved pins --deny-host for deny principals.
func TestExpand_DenyHostPreserved(t *testing.T) {
	p, _ := parseInvocation([]string{"kafka-acls", "--add", "--topic", "orders", "--operation", "Read", "--deny-principal", "User:bob", "--deny-host", "10.0.0.2"})
	rows, _ := expand(p, 1, extract.NewLogger())
	if len(rows) != 1 || rows[0].Host != "10.0.0.2" {
		t.Fatalf("--deny-host must be honored; got rows=%+v", rows)
	}
}

// TestExpand_ProducerGrantsCreate pins kafka-acls getProducerAcls semantics:
// --producer grants WRITE, DESCRIBE and CREATE on the topic.
func TestExpand_ProducerGrantsCreate(t *testing.T) {
	p, err := parseInvocation([]string{"kafka-acls", "--add", "--producer", "--topic", "orders", "--allow-principal", "User:alice"})
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := expand(p, 1, extract.NewLogger())
	ops := opsOn(rows, types.ResourceTopic, "orders")
	for _, want := range []types.Operation{types.OpWrite, types.OpDescribe, types.OpCreate} {
		if !ops[want] {
			t.Errorf("--producer must grant %s on the topic; got %v", want, ops)
		}
	}
}

// TestExpand_ProducerIdempotentGating pins that IdempotentWrite on Cluster is
// added ONLY when --idempotent is passed (the real CLI behaviour).
func TestExpand_ProducerIdempotentGating(t *testing.T) {
	hasClusterIdempotent := func(rows []types.ACLRow) bool {
		for _, r := range rows {
			if r.ResourceType == types.ResourceCluster && r.Operation == types.OpIdempotentWrite {
				return true
			}
		}
		return false
	}

	plain, _ := parseInvocation([]string{"kafka-acls", "--add", "--producer", "--topic", "orders", "--allow-principal", "User:alice"})
	rowsPlain, _ := expand(plain, 1, extract.NewLogger())
	if hasClusterIdempotent(rowsPlain) {
		t.Error("without --idempotent, no IdempotentWrite on Cluster should be emitted")
	}

	idem, _ := parseInvocation([]string{"kafka-acls", "--add", "--producer", "--idempotent", "--topic", "orders", "--allow-principal", "User:alice"})
	rowsIdem, _ := expand(idem, 1, extract.NewLogger())
	if !hasClusterIdempotent(rowsIdem) {
		t.Error("with --idempotent, IdempotentWrite on Cluster should be emitted")
	}
}

// TestExpand_ConsumerGroupReadOnly pins kafka-acls getConsumerAcls semantics:
// --consumer grants only READ on the group (not Describe).
func TestExpand_ConsumerGroupReadOnly(t *testing.T) {
	p, _ := parseInvocation([]string{"kafka-acls", "--add", "--consumer", "--topic", "orders", "--group", "g1", "--allow-principal", "User:alice"})
	rows, _ := expand(p, 1, extract.NewLogger())
	ops := opsOn(rows, types.ResourceGroup, "g1")
	if !ops[types.OpRead] {
		t.Error("--consumer must grant Read on the group")
	}
	if ops[types.OpDescribe] {
		t.Error("--consumer must NOT grant Describe on the group (kafka-acls grants only Read)")
	}
}
