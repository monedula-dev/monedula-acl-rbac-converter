// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package config_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
)

func TestParseAcknowledgements(t *testing.T) {
	data := []byte(`
acknowledgements:
  - acl_id: "deny-001"
    granting_rule: "DeveloperRead binding on Topic:*"
    operator: "michal.matloka@virtuslab.com"
    reason: "intentional: former employee, account offline"
`)
	got, err := config.ParseAcknowledgements(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d ack entries, want 1", len(got))
	}
	if got[0].ACLID != "deny-001" {
		t.Errorf("acl_id: got %q", got[0].ACLID)
	}
	if got[0].Operator != "michal.matloka@virtuslab.com" {
		t.Errorf("operator: got %q", got[0].Operator)
	}
}

func TestParseAcknowledgements_Empty(t *testing.T) {
	got, err := config.ParseAcknowledgements([]byte(``))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty should yield 0; got %d", len(got))
	}
}

func TestParseAcknowledgements_MissingFields(t *testing.T) {
	data := []byte(`
acknowledgements:
  - acl_id: "deny-001"
`)
	_, err := config.ParseAcknowledgements(data)
	if err == nil {
		t.Fatal("expected error for missing operator/reason")
	}
}
