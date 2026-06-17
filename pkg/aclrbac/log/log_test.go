// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package log_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/log"
)

func TestInit_TextFormat_WarnEmitsToStderr(t *testing.T) {
	var buf bytes.Buffer
	prev := log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	if err := log.Init(log.FormatText, "info"); err != nil {
		t.Fatal(err)
	}
	log.Warn("test warning", "key", "value")

	out := buf.String()
	if !strings.Contains(out, "test warning") {
		t.Errorf("expected 'test warning' in output; got %q", out)
	}
	if !strings.Contains(strings.ToUpper(out), "WARN") {
		t.Errorf("expected WARN level marker in output; got %q", out)
	}
}

func TestInit_JSONFormat_ProducesValidJSONLine(t *testing.T) {
	var buf bytes.Buffer
	prev := log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	if err := log.Init(log.FormatJSON, "info"); err != nil {
		t.Fatal(err)
	}
	log.Warn("json test", "field", "v")

	line := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}") {
		t.Errorf("expected JSON object; got %q", line)
	}
	if !strings.Contains(line, `"msg":"json test"`) {
		t.Errorf("expected msg field; got %q", line)
	}
}

func TestInit_LevelFilter_DebugBelowThresholdSilent(t *testing.T) {
	var buf bytes.Buffer
	prev := log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	if err := log.Init(log.FormatText, "warn"); err != nil {
		t.Fatal(err)
	}
	log.Info("should be silent")
	log.Debug("also silent")
	log.Warn("should appear")

	out := buf.String()
	if strings.Contains(out, "should be silent") || strings.Contains(out, "also silent") {
		t.Errorf("info/debug should be filtered at warn level; got %q", out)
	}
	if !strings.Contains(out, "should appear") {
		t.Errorf("warn should appear; got %q", out)
	}
}

func TestInit_InvalidLevel_ReturnsError(t *testing.T) {
	if err := log.Init(log.FormatText, "shout"); err == nil {
		t.Errorf("expected error for invalid level")
	}
}

func TestInit_InvalidFormat_ReturnsError(t *testing.T) {
	if err := log.Init(log.Format("yaml"), "info"); err == nil {
		t.Errorf("expected error for invalid format")
	}
}
