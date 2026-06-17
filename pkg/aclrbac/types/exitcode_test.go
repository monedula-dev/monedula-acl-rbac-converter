// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package types_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestExitCodeValues(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"Success", int(types.ExitSuccess), 0},
		{"Usage", int(types.ExitUsage), 1},
		{"Input", int(types.ExitInput), 2},
		{"Plan", int(types.ExitPlan), 3},
		{"External", int(types.ExitExternal), 4},
		{"Guardrail", int(types.ExitGuardrail), 5},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, c.got, c.want)
		}
	}
}
