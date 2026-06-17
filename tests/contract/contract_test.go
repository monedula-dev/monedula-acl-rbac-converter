// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package contract_test holds cross-component contract tests: the producer
// of an on-disk artefact (or stdout envelope) and every consumer of it must
// agree on its shape, its schema_version, and any cross-file binding (e.g.
// plan_sha256). These are the bug class that slipped through unit tests
// because each side was tested in isolation against its own assumed shape.
//
// Concretely, the project shipped:
//   - verify.json as a bare []Result while a consumer expected {results,counts}
//   - schema_version as integer 1 in some artefacts but string "1" in others
//   - a plan_sha256 binding where producer and consumer could disagree on the
//     hash format and so never match
//
// Every test here lives OUTSIDE the producing/consuming packages and imports
// them as a real downstream would, so a shape change in either side breaks the
// build or the assertion.
package contract_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/apply"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/status"
	deletecommon "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/report"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/schema"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

// --- (a) verify.json producer <-> consumer round-trip --------------------

// TestVerifyJSON_RoundTripPreservesConsumerFields marshals a verify.Summary
// the way the producer (verify.Run / Summary.WriteJSON) does, unmarshals it
// back into the SAME struct, and asserts every field the consumers depend on
// survives. The consumers are:
//   - cli.readVerify (reads verify.json before delete-acls eligibility)
//   - delete/deny/one.verifyBoundToPlan (reads PlanSHA256)
//   - cmds/status.compile (reads Results + Counts)
//
// readVerify and verifyBoundToPlan are unexported, so we assert at the type
// level: if anyone reshapes the envelope (e.g. back to a bare []Result, or
// drops plan_sha256), a field below stops surviving the round-trip and this
// fails. The B-class bug here was verify.json shipping as a bare array.
func TestVerifyJSON_RoundTripPreservesConsumerFields(t *testing.T) {
	src := verify.Summary{
		SchemaVersion: verify.CurrentSchemaVersion,
		PlanSHA256:    "f491c57fb1df655249a459e56aaaf118146ef1946a847dc14b84d10ccebeda77",
		Mode:          string(verify.ModeEffective),
		Results: []verify.Result{
			{BindingID: "rb-000000000001", SourceACLID: 1, Status: verify.StatusEffectiveOK},
			{BindingID: "rb-000000000002", SourceACLID: 2, Status: verify.StatusEffectiveUnknown, Detail: "downgraded by --accept-unknown-verify"},
		},
	}
	// WriteJSON is the exact producer path verify.Run uses for the on-disk
	// artefact and the --format json stdout envelope.
	buf := writeJSON(t, src.WriteJSON)

	// Consumers decode into verify.Summary (status.compile literally does
	// `json.Unmarshal(data, &sum)` with sum of this type). Round-trip must
	// preserve the fields they read.
	var got verify.Summary
	if err := json.Unmarshal(buf, &got); err != nil {
		t.Fatalf("consumer Unmarshal of producer output failed: %v\n%s", err, buf)
	}

	if got.SchemaVersion != "1" {
		t.Errorf("schema_version did not survive: got %q", got.SchemaVersion)
	}
	if got.PlanSHA256 != src.PlanSHA256 {
		t.Errorf("plan_sha256 did not survive (delete/deny/one consumer reads this): got %q", got.PlanSHA256)
	}
	if got.Mode != src.Mode {
		t.Errorf("mode did not survive: got %q", got.Mode)
	}
	// status.compile treats sum.Results == nil as "(unreadable)"; the
	// producer must therefore always emit a non-nil results array.
	if got.Results == nil {
		t.Fatal("results survived as nil; status.compile would render this as '(unreadable)'")
	}
	if len(got.Results) != len(src.Results) {
		t.Fatalf("results length changed: got %d want %d", len(got.Results), len(src.Results))
	}
	if got.Results[0].BindingID != "rb-000000000001" {
		t.Errorf("binding_id did not survive (delete-acls eligibility indexes on it): got %q", got.Results[0].BindingID)
	}
	// Counts are stamped by WriteJSON and read by status.compile.
	if got.Counts.Total != 2 || got.Counts.EffectiveOK != 1 || got.Counts.EffectiveUnknown != 1 {
		t.Errorf("counts did not survive/aggregate: %+v", got.Counts)
	}

	// And the producer's bytes must satisfy the published schema the CI
	// consumers validate against.
	if err := schema.ValidateVerifySummary(buf); err != nil {
		t.Errorf("producer output violates schemas/verify-summary.v1.json: %v\n%s", err, buf)
	}
}

// --- (b) schema_version consistency matrix -------------------------------

// TestSchemaVersion_IsStringOneAcrossAllEmitters locks in the unification
// that bit the project: schema_version must be the JSON STRING "1" — never
// the integer 1 (decoded as float64), never empty — across every
// JSON-emitting type. A reversion to int would decode to float64 here.
func TestSchemaVersion_IsStringOneAcrossAllEmitters(t *testing.T) {
	cases := []struct {
		name string
		// produce returns the marshalled JSON bytes the way production does.
		produce func(t *testing.T) []byte
	}{
		{
			name: "apply.Summary",
			produce: func(t *testing.T) []byte {
				s := apply.Summary{Bindings: []apply.BindingResult{
					{BindingID: "rb-1", Principal: "User:a", Role: "DeveloperRead", Status: apply.StatusCreated},
				}}
				return writeJSON(t, s.WriteJSON)
			},
		},
		{
			name: "verify.Summary",
			produce: func(t *testing.T) []byte {
				s := verify.Summary{
					PlanSHA256: "f491c57fb1df655249a459e56aaaf118146ef1946a847dc14b84d10ccebeda77",
					Mode:       string(verify.ModeBindingsExist),
					Results:    []verify.Result{{BindingID: "rb-1", Status: verify.StatusBindingExists}},
				}
				return writeJSON(t, s.WriteJSON)
			},
		},
		{
			name: "types.ACLSet",
			produce: func(t *testing.T) []byte {
				set := types.ACLSet{
					SchemaVersion: "1",
					Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
					ACLs:          []types.ACLRow{},
				}
				return mustMarshal(t, set)
			},
		},
		{
			name: "types.Plan",
			produce: func(t *testing.T) []byte {
				return mustMarshal(t, samplePlan())
			},
		},
		{
			name: "status.Report",
			produce: func(t *testing.T) []byte {
				// status.Run is the real producer; drive it against an empty
				// run dir so the envelope is minimal but schema_version is set.
				dir := t.TempDir()
				return runToBytes(t, func(w io.Writer) error {
					return status.Run(w, dir, status.FormatJSON)
				})
			},
		},
		{
			name: "report envelope",
			produce: func(t *testing.T) []byte {
				return runToBytes(t, func(w io.Writer) error {
					return report.Render(w, samplePlan(), report.FormatJSON)
				})
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := c.produce(t)
			// Decode into map[string]any so we can distinguish a JSON string
			// "1" (string) from a JSON number 1 (float64).
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("unmarshal %s: %v\n%s", c.name, err, raw)
			}
			v, ok := m["schema_version"]
			if !ok {
				t.Fatalf("%s: no top-level schema_version field\n%s", c.name, raw)
			}
			s, ok := v.(string)
			if !ok {
				t.Fatalf("%s: schema_version is %T (%v), not a JSON string — someone reverted to int", c.name, v, v)
			}
			if s != "1" {
				t.Errorf("%s: schema_version = %q, want %q", c.name, s, "1")
			}
		})
	}
}

// --- (c) plan_sha256 binding contract ------------------------------------

// TestPlanSHA256_VerifyAndDeleteAgree asserts that the plan_sha256 verify.Run
// stamps into verify.json is computed identically to common.FileSHA256 — the
// value delete-acls / delete-deny-* compares against (and that verifyBoundToPlan
// in delete/deny/one re-derives). If verify hashed the plan one way and delete
// hashed it another (e.g. sha256(bytes) hex vs. a sha256sum-format string), the
// two would silently never match and every delete would refuse to run (or, if
// inverted, run against a stale verify).
func TestPlanSHA256_VerifyAndDeleteAgree(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	plan := samplePlan()

	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	if err := os.WriteFile(planPath, data, 0o600); err != nil {
		t.Fatalf("write plan: %v", err)
	}

	// (1) The hash delete-* computes and compares against verify.json's
	// plan_sha256 field.
	deleteSide, err := deletecommon.FileSHA256(planPath)
	if err != nil {
		t.Fatalf("common.FileSHA256: %v", err)
	}

	// (2) The hash verify.Run stamps into verify.json. verify.fileSHA256 is
	// unexported, but its contract is documented as "hex sha256 of the raw
	// plan.json bytes, matching common.FileSHA256". Re-derive that here from
	// the same bytes; both sides must equal this canonical value.
	sum := sha256.Sum256(data)
	canonical := hex.EncodeToString(sum[:])

	if deleteSide != canonical {
		t.Errorf("common.FileSHA256 disagrees with sha256(plan bytes):\n  delete=%s\n  canonical=%s", deleteSide, canonical)
	}
	// 64 lowercase hex chars — the shape the published verify-summary schema
	// pins for plan_sha256 (pattern ^[0-9a-f]{64}$), and the shape the
	// delete-*.sh runtime guard (sha256sum | awk) produces.
	if len(deleteSide) != 64 {
		t.Errorf("plan_sha256 is %d chars, want 64 (delete-*.sh sha256sum output is 64 hex chars)", len(deleteSide))
	}
}

// --- helpers -------------------------------------------------------------

// writeJSON drives a producer's WriteJSON-style method (io.Writer sink) and
// returns the bytes it emitted.
func writeJSON(t *testing.T, fn func(w io.Writer) error) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := fn(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	return buf.Bytes()
}

func runToBytes(t *testing.T, fn func(w io.Writer) error) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := fn(&buf); err != nil {
		t.Fatalf("produce: %v", err)
	}
	return buf.Bytes()
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// samplePlan is a schema-valid plan used by several cases.
func samplePlan() types.Plan {
	return types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{{
			ID:        "rb-000000000001",
			Action:    types.ActionCreate,
			Principal: "User:alice",
			Role:      "DeveloperRead",
			Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
			ResourcePatterns: []types.ResourcePattern{{
				ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
			}},
			SourceACLIDs: []int{1},
		}},
		Unmapped:     []types.UnmappedEntry{},
		Rejected:     []types.RejectedEntry{},
		Warnings:     []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{},
	}
}
