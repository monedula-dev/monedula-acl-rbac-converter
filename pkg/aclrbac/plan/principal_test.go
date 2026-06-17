// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
)

func TestMapPrincipal_DirectMap(t *testing.T) {
	p := config.Principals{
		Mappings: map[string]string{"User:svc-billing": "Group:billing-services"},
		Fallback: config.PrincipalFallbackPassThrough,
	}
	r, err := plan.MapPrincipal("User:svc-billing", p)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if r.Resolved != "Group:billing-services" {
		t.Errorf("got %q", r.Resolved)
	}
	if r.PassedThrough {
		t.Errorf("direct map should not be flagged passed-through")
	}
}

func TestMapPrincipal_PassThrough(t *testing.T) {
	p := config.Principals{
		Fallback: config.PrincipalFallbackPassThrough,
	}
	r, err := plan.MapPrincipal("User:alice", p)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if r.Resolved != "User:alice" {
		t.Errorf("got %q", r.Resolved)
	}
	if !r.PassedThrough {
		t.Errorf("missing mapping should flag passed-through")
	}
}

func TestMapPrincipal_MTLSDNWarns(t *testing.T) {
	p := config.Principals{
		Fallback: config.PrincipalFallbackPassThrough,
	}
	r, err := plan.MapPrincipal("User:CN=alice,O=acme,C=US", p)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if !r.LooksLikeMTLSDN {
		t.Errorf("CN=...,O=... should be detected as mTLS DN")
	}
}

func TestMapPrincipal_FallbackFail(t *testing.T) {
	p := config.Principals{
		Fallback: config.PrincipalFallbackFail,
	}
	_, err := plan.MapPrincipal("User:unmapped", p)
	if err == nil {
		t.Errorf("fallback=fail should error for unmapped principal")
	}
}
