// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package log wraps stdlib log/slog with two configurable output formats
// (text for humans, JSON for machine consumers) and a redirectable sink
// for tests. The package is intentionally tiny; new code should call
// slog directly via the helpers below.
package log

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Format selects the slog handler output style.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

var (
	mu         sync.RWMutex
	out        io.Writer = os.Stderr
	currentLvl           = slog.LevelInfo
	currentFmt           = FormatText
)

// Init configures the default slog logger with the given format and
// level. Returns an error for unrecognized values without touching the
// existing configuration.
func Init(format Format, level string) error {
	lvl, err := parseLevel(level)
	if err != nil {
		return err
	}
	if format != FormatText && format != FormatJSON {
		return fmt.Errorf("log: unknown format %q (want text|json)", format)
	}
	mu.Lock()
	defer mu.Unlock()
	currentLvl = lvl
	currentFmt = format
	rebuildLocked()
	return nil
}

// SetOutput redirects log output. Returns the previous writer so tests
// can restore on cleanup. Re-applies the current format/level.
func SetOutput(w io.Writer) io.Writer {
	mu.Lock()
	defer mu.Unlock()
	prev := out
	out = w
	rebuildLocked()
	return prev
}

func rebuildLocked() {
	opts := &slog.HandlerOptions{Level: currentLvl}
	var h slog.Handler
	switch currentFmt {
	case FormatJSON:
		h = slog.NewJSONHandler(out, opts)
	default:
		h = slog.NewTextHandler(out, opts)
	}
	slog.SetDefault(slog.New(h))
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return slog.LevelInfo, fmt.Errorf("log: unknown level %q (want debug|info|warn|error)", s)
}

// Warn / Info / Error / Debug forward to the default slog logger. Pass
// alternating key/value pairs after msg to attach structured attrs.
func Warn(msg string, args ...any)  { slog.Warn(msg, args...) }
func Info(msg string, args ...any)  { slog.Info(msg, args...) }
func Error(msg string, args ...any) { slog.Error(msg, args...) }
func Debug(msg string, args ...any) { slog.Debug(msg, args...) }
