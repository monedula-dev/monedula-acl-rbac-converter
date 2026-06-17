// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package verify

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSummary_AggregateCounts(t *testing.T) {
	s := Summary{Results: []Result{
		{Status: StatusEffectiveOK},
		{Status: StatusEffectiveOK},
		{Status: StatusEffectiveMissing},
		{Status: StatusEffectiveUnknown},
		{Status: StatusEffectiveUnknown},
		{Status: StatusEffectiveUnknown},
		{Status: StatusBindingExists}, // counted in total only
	}}
	c := s.AggregateCounts()
	if c.Total != 7 {
		t.Errorf("Total: got %d, want 7", c.Total)
	}
	if c.EffectiveOK != 2 {
		t.Errorf("EffectiveOK: got %d, want 2", c.EffectiveOK)
	}
	if c.EffectiveMissing != 1 {
		t.Errorf("EffectiveMissing: got %d, want 1", c.EffectiveMissing)
	}
	if c.EffectiveUnknown != 3 {
		t.Errorf("EffectiveUnknown: got %d, want 3", c.EffectiveUnknown)
	}
}

func TestSummary_WriteText(t *testing.T) {
	s := Summary{Results: []Result{
		{Status: StatusEffectiveOK},
		{Status: StatusEffectiveMissing},
		{Status: StatusEffectiveUnknown},
	}}
	var buf bytes.Buffer
	if err := s.WriteText(&buf); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	for _, kw := range []string{"EFFECTIVE_OK", "missing", "unknown", "total"} {
		if !strings.Contains(out, kw) {
			t.Errorf("output %q missing keyword %q", out, kw)
		}
	}
}

// TestSummary_WriteText_BindingsExistMode is the mode-aware-rendering
// regression guard: in `--mode bindings-exist`, the summary must NOT show
// `0 EFFECTIVE_OK, 0 missing, 0 unknown` (the disjoint-counter set is empty)
// and must instead report `N bindings present, M missing`.
func TestSummary_WriteText_BindingsExistMode(t *testing.T) {
	s := Summary{Results: []Result{
		{BindingID: "b1", Status: StatusBindingExists},
		{BindingID: "b2", Status: StatusBindingExists},
		{BindingID: "b3", Status: StatusBindingMissing},
	}}
	var buf bytes.Buffer
	if err := s.WriteText(&buf); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	for _, kw := range []string{"2 bindings present", "1 missing", "3 total"} {
		if !strings.Contains(out, kw) {
			t.Errorf("bindings-exist text output should contain %q; got %q", kw, out)
		}
	}
	if strings.Contains(out, "EFFECTIVE_OK") {
		t.Errorf("bindings-exist mode must NOT print the EFFECTIVE_* line (got %q)", out)
	}
}

func TestSummary_WriteJSON_Roundtrip(t *testing.T) {
	s := Summary{Results: []Result{
		{BindingID: "b1", Status: StatusEffectiveOK},
		{SourceACLID: 7, Status: StatusEffectiveMissing, Detail: "no binding"},
	}}
	var buf bytes.Buffer
	if err := s.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var got Summary
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v\nbody:\n%s", err, buf.String())
	}
	if len(got.Results) != 2 {
		t.Fatalf("Results len: got %d, want 2", len(got.Results))
	}
	if got.Results[0].BindingID != "b1" || got.Results[0].Status != StatusEffectiveOK {
		t.Errorf("Results[0] = %+v", got.Results[0])
	}
	if got.Results[1].SourceACLID != 7 || got.Results[1].Detail != "no binding" {
		t.Errorf("Results[1] = %+v", got.Results[1])
	}
	if got.Counts.Total != 2 || got.Counts.EffectiveOK != 1 || got.Counts.EffectiveMissing != 1 {
		t.Errorf("Counts = %+v", got.Counts)
	}
}
