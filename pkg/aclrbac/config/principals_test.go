// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package config_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
)

func TestParsePrincipals(t *testing.T) {
	data := []byte(`
principals:
  "User:CN=alice,O=acme,C=US": "User:alice@acme.com"
  "User:svc-billing": "Group:billing-services"
fallback: pass-through
`)
	got, err := config.ParsePrincipals(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Mappings["User:svc-billing"] != "Group:billing-services" {
		t.Errorf("svc-billing: got %q", got.Mappings["User:svc-billing"])
	}
	if got.Fallback != config.PrincipalFallbackPassThrough {
		t.Errorf("fallback: got %q, want pass-through", got.Fallback)
	}
}

func TestParsePrincipals_FallbackFail(t *testing.T) {
	got, err := config.ParsePrincipals([]byte(`fallback: fail`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Fallback != config.PrincipalFallbackFail {
		t.Errorf("fallback: got %q, want fail", got.Fallback)
	}
}

func TestParsePrincipals_InvalidFallback(t *testing.T) {
	_, err := config.ParsePrincipals([]byte(`fallback: bogus`))
	if err == nil {
		t.Fatal("expected error for invalid fallback")
	}
}

func TestParsePrincipals_RejectsEmptyMappingValue(t *testing.T) {
	// An empty mapping target would make MapPrincipal resolve to "" and the
	// planner would emit a binding with an empty principal.
	_, err := config.ParsePrincipals([]byte("principals:\n  \"User:alice\": \"\"\n"))
	if err == nil {
		t.Error("expected error for empty mapping value")
	}
}

func TestParsePrincipals_DefaultFallback(t *testing.T) {
	got, err := config.ParsePrincipals([]byte(``))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Fallback != config.PrincipalFallbackPassThrough {
		t.Errorf("default fallback: got %q, want pass-through", got.Fallback)
	}
}
