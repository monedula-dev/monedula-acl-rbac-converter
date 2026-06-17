// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ConfirmInput feeds Confirm.
type ConfirmInput struct {
	ConfirmFlag bool
	IsTTY       bool
	Stdin       io.Reader
	Stdout      io.Writer
	Summary     string
}

// Confirm enforces the §5 "no mutation without confirmation" rule.
func Confirm(in ConfirmInput) (bool, error) {
	if in.ConfirmFlag {
		return true, nil
	}
	if !in.IsTTY {
		return false, NewUsageError("--confirm is required when stdin is not a TTY")
	}
	out := in.Stdout
	if out == nil {
		out = os.Stderr
	}
	if in.Summary != "" {
		fmt.Fprintln(out, in.Summary)
	}
	fmt.Fprint(out, "Type 'yes' to continue: ")
	r := bufio.NewReader(in.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(strings.ToLower(line)) != "yes" {
		return false, NewUsageError("confirmation refused")
	}
	return true, nil
}

// StdinIsTTY reports whether os.Stdin is a TTY.
func StdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
