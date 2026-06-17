// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli_test

// Non-interactive Confirm tests.
//
// Interactive TTY paths (StdinIsTTY == true, user types "yes"/"no") are
// covered by the pty-based tests in confirm_pty_linux_test.go which only run
// on Linux. The paths here are practical on all platforms.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestConfirm_ConfirmFlagBypassesPrompt: --confirm flag set means Confirm
// returns (true, nil) without reading from stdin at all.
func TestConfirm_ConfirmFlagBypassesPrompt(t *testing.T) {
	var out bytes.Buffer
	ok, err := cli.Confirm(cli.ConfirmInput{
		ConfirmFlag: true,
		IsTTY:       false,
		Stdin:       strings.NewReader(""),
		Stdout:      &out,
		Summary:     "apply plan.json",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true when --confirm flag is set")
	}
}

// TestConfirm_NonTTY_NoConfirmFlag_ReturnsUsageError: stdin is not a TTY and
// --confirm is not set → return false + usageError mapping to ExitUsage.
func TestConfirm_NonTTY_NoConfirmFlag_ReturnsUsageError(t *testing.T) {
	var out bytes.Buffer
	ok, err := cli.Confirm(cli.ConfirmInput{
		ConfirmFlag: false,
		IsTTY:       false,
		Stdin:       bytes.NewBufferString(""),
		Stdout:      &out,
	})
	if ok {
		t.Error("expected ok=false when stdin is not a TTY and --confirm is not set")
	}
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if code := cli.MapError(err); code != types.ExitUsage {
		t.Errorf("expected ExitUsage (1), got %d", code)
	}
	if !strings.Contains(err.Error(), "--confirm") {
		t.Errorf("error should mention --confirm; got: %v", err)
	}
}

// TestConfirm_TTY_YesAccepted: when IsTTY is true and stdin provides "yes",
// Confirm returns (true, nil).
func TestConfirm_TTY_YesAccepted(t *testing.T) {
	var out bytes.Buffer
	ok, err := cli.Confirm(cli.ConfirmInput{
		ConfirmFlag: false,
		IsTTY:       true,
		Stdin:       strings.NewReader("yes\n"),
		Stdout:      &out,
		Summary:     "test summary",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for 'yes' input")
	}
}

// TestConfirm_TTY_NoRefused: when IsTTY is true and user types "no",
// Confirm returns (false, usageError) with ExitUsage exit code.
func TestConfirm_TTY_NoRefused(t *testing.T) {
	var out bytes.Buffer
	ok, err := cli.Confirm(cli.ConfirmInput{
		ConfirmFlag: false,
		IsTTY:       true,
		Stdin:       strings.NewReader("no\n"),
		Stdout:      &out,
	})
	if ok {
		t.Error("expected ok=false for 'no' input")
	}
	if err == nil {
		t.Fatal("expected non-nil error on refusal")
	}
	if code := cli.MapError(err); code != types.ExitUsage {
		t.Errorf("expected ExitUsage (1), got %d", code)
	}
}

// TestConfirm_TTY_YesCaseInsensitive: "YES" and "Yes" should also be accepted.
func TestConfirm_TTY_YesCaseInsensitive(t *testing.T) {
	for _, input := range []string{"YES\n", "Yes\n", " yes \n"} {
		var out bytes.Buffer
		ok, err := cli.Confirm(cli.ConfirmInput{
			ConfirmFlag: false,
			IsTTY:       true,
			Stdin:       strings.NewReader(input),
			Stdout:      &out,
		})
		if err != nil || !ok {
			t.Errorf("input %q: expected (true, nil), got (%v, %v)", input, ok, err)
		}
	}
}

// TestConfirm_SummaryPrinted: when IsTTY is true and Summary is set, the
// summary should appear in the output before the prompt.
func TestConfirm_SummaryPrinted(t *testing.T) {
	var out bytes.Buffer
	_, _ = cli.Confirm(cli.ConfirmInput{
		ConfirmFlag: false,
		IsTTY:       true,
		Stdin:       strings.NewReader("yes\n"),
		Stdout:      &out,
		Summary:     "applying DeveloperRead for alice",
	})
	if !strings.Contains(out.String(), "applying DeveloperRead for alice") {
		t.Errorf("summary not printed; got: %q", out.String())
	}
}
