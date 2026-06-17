// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/log"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Typed errors used by command handlers. MapError() returns the spec §5.4
// exit code for each.

type usageError struct{ msg string }
type inputError struct{ msg string }
type planError struct{ msg string }
type guardrailError struct{ msg string }
type externalError struct{ msg string }

func (e *usageError) Error() string     { return "usage: " + e.msg }
func (e *inputError) Error() string     { return "input: " + e.msg }
func (e *planError) Error() string      { return "plan: " + e.msg }
func (e *guardrailError) Error() string { return "guardrail: " + e.msg }
func (e *externalError) Error() string  { return "external: " + e.msg }

// NewUsageError returns an error that maps to exit code 1.
func NewUsageError(msg string) error { return &usageError{msg: msg} }

// NewInputError returns an error that maps to exit code 2.
func NewInputError(msg string) error { return &inputError{msg: msg} }

// NewPlanError returns an error that maps to exit code 3.
func NewPlanError(msg string) error { return &planError{msg: msg} }

// NewGuardrailError returns an error that maps to exit code 5.
func NewGuardrailError(msg string) error { return &guardrailError{msg: msg} }

// NewExternalError returns an error that maps to exit code 4.
func NewExternalError(msg string) error { return &externalError{msg: msg} }

// isCobraUsageError detects cobra's own argument/command parse failures
// (unknown command, wrong arg count, required-flag-not-set) so they map to
// ExitUsage (1) per the §5.4 contract rather than the ExitExternal (4)
// fallback. Flag-parse errors are already wrapped via root.SetFlagErrorFunc;
// these cover the messages cobra returns without a hook.
func isCobraUsageError(err error) bool {
	msg := err.Error()
	for _, p := range []string{
		"unknown command",
		"unknown flag",
		"unknown shorthand flag",
		"accepts ", // "accepts N arg(s), received M"
		"requires at least",
		"required flag(s)",
		"invalid argument",
	} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

// MapError applies the §5.4 table.
func MapError(err error) types.ExitCode {
	if err == nil {
		return types.ExitSuccess
	}

	var ue *usageError
	if errors.As(err, &ue) {
		return types.ExitUsage
	}
	var ie *inputError
	if errors.As(err, &ie) {
		return types.ExitInput
	}
	var pe *planError
	if errors.As(err, &pe) {
		return types.ExitPlan
	}
	var ee *externalError
	if errors.As(err, &ee) {
		return types.ExitExternal
	}
	var ge *guardrailError
	if errors.As(err, &ge) {
		return types.ExitGuardrail
	}

	if isCobraUsageError(err) {
		return types.ExitUsage
	}
	if mds.IsAuthError(err) {
		return types.ExitExternal
	}
	if errors.Is(err, rundir.ErrChecksumMismatch) {
		return types.ExitGuardrail
	}

	// Unrecognised error class. Categorise as External (4) — the spec's
	// best-fit bucket for "something went wrong I can't classify."
	// Reporting as Usage (1) would mislead operators into looking for a
	// flag typo. Log the actual type so post-mortems can identify the
	// gap and add an explicit mapping. This is a maintainer diagnostic;
	// demoted from Warn so operators don't see noise on errors from
	// cmds/* that weren't wrapped with typed cli errors (most fmt.Errorf
	// returns are bare *errors.errorString and fall through here).
	log.Debug("MapError: unrecognised error type; reporting as external",
		"type", fmt.Sprintf("%T", err),
		"error", err.Error())
	return types.ExitExternal
}
