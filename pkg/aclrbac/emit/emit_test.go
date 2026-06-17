// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package emit_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestOrderedBindings_DeterministicByID(t *testing.T) {
	in := []types.Binding{
		{ID: "rb-bbbbbbbbbbbb", Principal: "User:bob"},
		{ID: "rb-aaaaaaaaaaaa", Principal: "User:alice"},
		{ID: "rb-cccccccccccc", Principal: "User:carol"},
	}
	got := emit.OrderedBindings(in)
	if got[0].ID != "rb-aaaaaaaaaaaa" || got[2].ID != "rb-cccccccccccc" {
		t.Errorf("not sorted by id: %+v", got)
	}
}

func TestOrderedBindings_SkipExistsLast(t *testing.T) {
	in := []types.Binding{
		{ID: "rb-aaaaaaaaaaaa", Action: types.ActionSkipExists},
		{ID: "rb-bbbbbbbbbbbb", Action: types.ActionCreate},
	}
	got := emit.OrderedBindings(in)
	if got[0].Action != types.ActionCreate {
		t.Errorf("CREATE should come before SKIP_EXISTS; got %+v", got)
	}
}
