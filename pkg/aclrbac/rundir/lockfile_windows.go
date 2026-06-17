// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build windows

package rundir

import (
	"syscall"
)

const (
	processQueryLimitedInformation = 0x1000
	errorInvalidParameter          = 87
)

// processAlive returns true if a process with the given PID exists on this
// Windows host. Uses OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION:
// success means the process exists; ERROR_INVALID_PARAMETER means it does
// not.
func processAlive(pid int) bool {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == errorInvalidParameter {
			return false
		}
		// Other errors (access denied, etc.) — be conservative and assume
		// the process is alive so the operator's lock isn't stolen.
		return true
	}
	syscall.CloseHandle(h)
	return true
}
