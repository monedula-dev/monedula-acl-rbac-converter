// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestExecute_CobraUsageErrorsExitUsage pins that cobra's own parse failures
// (unknown command, unknown flag, wrong arg count) exit with ExitUsage (1),
// not the ExitExternal (4) fallback — a typo must not look like an
// infrastructure failure to CI.
func TestExecute_CobraUsageErrorsExitUsage(t *testing.T) {
	cases := [][]string{
		{"definitely-not-a-command"},
		{"extract", "--definitely-not-a-flag"},
		{"status"}, // status RUNDIR requires exactly 1 arg
	}
	for _, args := range cases {
		if got := cli.Execute(args); got != int(types.ExitUsage) {
			t.Errorf("Execute(%v) = %d, want ExitUsage (%d)", args, got, types.ExitUsage)
		}
	}
}

func TestMapError_Nil(t *testing.T) {
	if got := cli.MapError(nil); got != types.ExitSuccess {
		t.Errorf("nil error: want %d, got %d", types.ExitSuccess, got)
	}
}

func TestMapError_UsageError(t *testing.T) {
	err := cli.NewUsageError("missing --flag")
	if got := cli.MapError(err); got != types.ExitUsage {
		t.Errorf("usageError: want %d, got %d", types.ExitUsage, got)
	}
}

func TestMapError_InputError(t *testing.T) {
	err := cli.NewInputError("bad JSON")
	if got := cli.MapError(err); got != types.ExitInput {
		t.Errorf("inputError: want %d, got %d", types.ExitInput, got)
	}
}

func TestMapError_PlanError(t *testing.T) {
	err := cli.NewPlanError("unmapped ACLs")
	if got := cli.MapError(err); got != types.ExitPlan {
		t.Errorf("planError: want %d, got %d", types.ExitPlan, got)
	}
}

func TestMapError_ExternalError(t *testing.T) {
	err := cli.NewExternalError("MDS unreachable")
	if got := cli.MapError(err); got != types.ExitExternal {
		t.Errorf("externalError: want %d, got %d", types.ExitExternal, got)
	}
}

func TestMapError_GuardrailError(t *testing.T) {
	err := cli.NewGuardrailError("checksum mismatch")
	if got := cli.MapError(err); got != types.ExitGuardrail {
		t.Errorf("guardrailError: want %d, got %d", types.ExitGuardrail, got)
	}
}

func TestMapError_ChecksumMismatch(t *testing.T) {
	// rundir.ErrChecksumMismatch must map to ExitGuardrail (5).
	err := fmt.Errorf("wrapped: %w", rundir.ErrChecksumMismatch)
	if got := cli.MapError(err); got != types.ExitGuardrail {
		t.Errorf("ErrChecksumMismatch: want %d, got %d", types.ExitGuardrail, got)
	}
}

func TestMapError_UnknownError_FallsThrough(t *testing.T) {
	// An error that doesn't match any typed bucket should fall through to
	// ExitExternal (4) rather than misleading operators with ExitUsage (1).
	err := errors.New("some random error")
	if got := cli.MapError(err); got != types.ExitExternal {
		t.Errorf("unknown error: want %d (ExitExternal), got %d", types.ExitExternal, got)
	}
}

// TestMapError_AuthError asserts an mds.HTTPError carrying a 401 maps to
// ExitExternal. Previously this path was exercised via an httptest server
// whose error could be t.Skip'd away — a fake-passing test. Construct the
// HTTPError directly so the assertion always runs.
func TestMapError_AuthError(t *testing.T) {
	err := &mds.HTTPError{StatusCode: 401, Body: "unauthorized"}
	if got := cli.MapError(err); got != types.ExitExternal {
		t.Errorf("MapError(HTTPError{401}) = %d, want ExitExternal (%d)", got, types.ExitExternal)
	}
}

// TestMapError_ForbiddenError covers the 403 branch of mds.IsAuthError.
func TestMapError_ForbiddenError(t *testing.T) {
	err := &mds.HTTPError{StatusCode: 403, Body: "forbidden"}
	if got := cli.MapError(err); got != types.ExitExternal {
		t.Errorf("MapError(HTTPError{403}) = %d, want ExitExternal (%d)", got, types.ExitExternal)
	}
}

func TestMapError_WrappedUsageError(t *testing.T) {
	inner := cli.NewUsageError("inner")
	wrapped := fmt.Errorf("outer: %w", inner)
	if got := cli.MapError(wrapped); got != types.ExitUsage {
		t.Errorf("wrapped usageError: want %d, got %d", types.ExitUsage, got)
	}
}

func TestErrorMessages(t *testing.T) {
	cases := []struct {
		err     error
		wantPfx string
	}{
		{cli.NewUsageError("x"), "usage: x"},
		{cli.NewInputError("x"), "input: x"},
		{cli.NewPlanError("x"), "plan: x"},
		{cli.NewExternalError("x"), "external: x"},
		{cli.NewGuardrailError("x"), "guardrail: x"},
	}
	for _, c := range cases {
		if got := c.err.Error(); got != c.wantPfx {
			t.Errorf("Error() = %q, want %q", got, c.wantPfx)
		}
	}
}
