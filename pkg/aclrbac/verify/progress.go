// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package verify

import (
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/term"
)

// Progress writes one-line per-binding progress to stderr when stderr is a
// TTY. Non-TTY callers (CI) get no output.
//
// verify.Run calls Printf from parallel goroutines (--verify-parallelism), so
// the underlying writer access is serialized through mu. Even when the writer
// is os.Stderr (which the OS serializes on write(2)), interleaved fmt.Fprintf
// arguments would produce garbled lines; mu prevents that as well.
type Progress struct {
	mu      sync.Mutex
	w       io.Writer
	enabled bool
}

// NewProgress returns a Progress sink targeting os.Stderr.
func NewProgress(force bool) *Progress {
	enabled := force || term.IsTerminal(int(os.Stderr.Fd()))
	return &Progress{w: os.Stderr, enabled: enabled}
}

// NewProgressWriter returns a Progress targeting an explicit writer.
// enabled controls whether output happens regardless of TTY status.
// Useful for tests and for forcing progress in non-TTY environments.
func NewProgressWriter(w io.Writer, enabled bool) *Progress {
	return &Progress{w: w, enabled: enabled}
}

func (p *Progress) Printf(format string, args ...interface{}) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, format, args...)
}
