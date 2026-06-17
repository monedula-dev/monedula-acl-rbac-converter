// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build !windows

package rundir

import (
	"os"
	"syscall"
)

// processAlive returns true if a process with the given PID exists on this
// host. Unix implementation uses signal 0 — a no-op probe.
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
