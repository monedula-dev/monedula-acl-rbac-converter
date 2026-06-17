// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package script_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/script"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestExtract_Basic(t *testing.T) {
	a, _ := script.New("testdata/basic.sh", nil, false)
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 2 {
		t.Errorf("got %d ACLs", len(set.ACLs))
	}
	if set.ACLs[0].Principal != "User:alice" {
		t.Errorf("principal: %q", set.ACLs[0].Principal)
	}
}

func TestExtract_DockerWrapped(t *testing.T) {
	a, _ := script.New("testdata/docker-wrapped.sh", nil, false)
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 1 {
		t.Errorf("got %d ACLs", len(set.ACLs))
	}
	if set.ACLs[0].ResourceType != types.ResourceGroup {
		t.Errorf("resource type: %q", set.ACLs[0].ResourceType)
	}
}

func TestExtract_ProducerConsumerExpansion(t *testing.T) {
	a, _ := script.New("testdata/producer-consumer.sh", nil, false)
	set, _, _, log, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) < 6 {
		t.Errorf("producer+consumer expansion should produce >=6 rows; got %d", len(set.ACLs))
	}
	if !strings.Contains(string(log.Bytes()), "EXPANDED --producer") {
		t.Errorf("expected expansion log line; got:\n%s", log.Bytes())
	}
}

func TestExtract_ControlFlowRejected(t *testing.T) {
	a, _ := script.New("testdata/rejected-control-flow.sh", nil, false)
	_, _, _, _, err := a.Extract()
	if err == nil {
		t.Fatal("expected error for control flow")
	}
	if !strings.Contains(err.Error(), "control flow") && !strings.Contains(err.Error(), "ForClause") {
		t.Errorf("error should mention control flow / ForClause: %v", err)
	}
}

// TestExtract_MalformedKafkaAclsErrors pins that a recognized kafka-acls
// --add invocation that fails to parse (here a --topic flag with no value)
// surfaces a hard error rather than being silently skipped as "not a
// kafka-acls call".
func TestExtract_MalformedKafkaAclsErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.sh")
	body := "kafka-acls --add --allow-principal User:alice --operation Read --topic\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := script.New(path, nil, false)
	if _, _, _, _, err := a.Extract(); err == nil {
		t.Fatal("expected error for a malformed kafka-acls --add command, got nil (silently skipped)")
	}
}

func TestExtract_VariableSubstitution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vars.sh")
	body := `kafka-acls --add --allow-principal User:alice --operation Read --topic "$TOPIC"` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := script.New(path, map[string]string{"TOPIC": "orders"}, false)
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract with vars: %v", err)
	}
	if set.ACLs[0].ResourceName != "orders" {
		t.Errorf("topic: got %q", set.ACLs[0].ResourceName)
	}

	a2, _ := script.New(path, nil, false)
	if _, _, _, _, err := a2.Extract(); err == nil {
		t.Fatal("expected error for unresolved variable")
	}
}

func TestExtract_RemoveRejectedByDefault_AllowedWithFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rm.sh")
	body := "kafka-acls --remove --allow-principal User:alice --topic orders --operation Read\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a, _ := script.New(path, nil, false)
	if _, _, _, _, err := a.Extract(); err == nil {
		t.Fatal("expected error for --remove without --ignore-non-add")
	}

	a2, _ := script.New(path, nil, true)
	set, _, _, _, err := a2.Extract()
	if err != nil {
		t.Fatalf("extract with ignore-non-add: %v", err)
	}
	if len(set.ACLs) != 0 {
		t.Errorf("--remove should be skipped, not converted; got %d ACLs", len(set.ACLs))
	}
}
