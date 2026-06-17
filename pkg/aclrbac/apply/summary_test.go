// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package apply_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/apply"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/schema"
)

func TestSummary_RenderText(t *testing.T) {
	s := apply.Summary{
		Bindings: []apply.BindingResult{
			{BindingID: "rb-aaa", Principal: "User:alice", Role: "DeveloperRead", Status: apply.StatusCreated},
			{BindingID: "rb-bbb", Principal: "User:bob", Role: "DeveloperWrite", Status: apply.StatusSkipExists},
			{BindingID: "rb-ccc", Principal: "User:carol", Role: "ResourceOwner", Status: apply.StatusFailed, Error: "MDS returned 503"},
		},
	}
	var buf bytes.Buffer
	if err := s.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"1 created", "1 skipped", "1 failed", "User:carol", "MDS returned 503"} {
		if !strings.Contains(out, want) {
			t.Errorf("text summary missing %q:\n%s", want, out)
		}
	}
}

func TestSummary_RenderJSON_ParsesBack(t *testing.T) {
	s := apply.Summary{
		Bindings: []apply.BindingResult{
			{BindingID: "rb-aaa", Principal: "User:alice", Role: "DeveloperRead", Status: apply.StatusCreated},
			{BindingID: "rb-bbb", Principal: "User:bob", Role: "DeveloperWrite", Status: apply.StatusSkipExists},
		},
	}
	var buf bytes.Buffer
	if err := s.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}

	var got apply.Summary
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("JSON summary does not round-trip: %v\noutput:\n%s", err, buf.String())
	}
	if len(got.Bindings) != 2 {
		t.Errorf("expected 2 bindings; got %d", len(got.Bindings))
	}
	if got.Bindings[0].Status != apply.StatusCreated {
		t.Errorf("status round-trip: got %q", got.Bindings[0].Status)
	}
	if got.Counts.Created != 1 || got.Counts.SkipExists != 1 {
		t.Errorf("counts in JSON: %+v", got.Counts)
	}
}

func TestSummary_Counts_Aggregate(t *testing.T) {
	s := apply.Summary{
		Bindings: []apply.BindingResult{
			{Status: apply.StatusCreated},
			{Status: apply.StatusCreated},
			{Status: apply.StatusSkipExists},
			{Status: apply.StatusFailed, Error: "x"},
		},
	}
	c := s.AggregateCounts()
	if c.Created != 2 || c.SkipExists != 1 || c.Failed != 1 || c.Total != 4 {
		t.Errorf("counts: %+v", c)
	}
}

// TestRun_EmitsTextSummary_OnStdoutWriter exercises apply.Run end-to-end
// against a fake MDS and asserts the text summary lands on the
// configured writer.
func TestRun_EmitsTextSummary_OnStdoutWriter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/roles/") {
			w.WriteHeader(204)
			return
		}
		_, _ = w.Write([]byte(`{"rolebindings":{}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	mustWritePlanAndChecksum(t, planPath, twoBindingPlan())

	var buf bytes.Buffer
	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	if err := apply.Run(apply.Options{
		RunDir:        dir,
		PlanPath:      planPath,
		Client:        cl,
		SummaryWriter: &buf,
		// SummaryFormat empty -> default text
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"2 created", "0 skipped", "0 failed", "(2 total)"} {
		if !strings.Contains(out, want) {
			t.Errorf("text summary missing %q:\n%s", want, out)
		}
	}
}

// TestSummary_DryRunText_PrefixAndVerbs asserts the dry-run text output
// uses the "(dry-run)" prefix and "would create / would skip" verbs,
// distinguishing it from a real apply summary at a glance.
func TestSummary_DryRunText_PrefixAndVerbs(t *testing.T) {
	s := apply.Summary{
		Bindings: []apply.BindingResult{
			{BindingID: "rb-aaa", Principal: "User:alice", Role: "DeveloperRead", Status: apply.StatusWouldCreate},
			{BindingID: "rb-bbb", Principal: "User:bob", Role: "DeveloperWrite", Status: apply.StatusWouldCreate},
			{BindingID: "rb-ccc", Principal: "User:carol", Role: "ResourceOwner", Status: apply.StatusWouldSkip},
		},
	}
	var buf bytes.Buffer
	if err := s.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"apply (dry-run):", "2 would create", "1 would skip", "(3 total)"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run text summary missing %q:\n%s", want, out)
		}
	}
	// And we MUST NOT slip "created" / "skipped" verbs into a dry-run
	// summary — that would confuse CI scripts that grep stdout.
	if strings.Contains(out, "apply: ") {
		t.Errorf("dry-run summary leaked production prefix:\n%s", out)
	}
}

// TestSummary_DryRunJSON_RoundTrips asserts the dry-run JSON envelope
// uses the same fields as production Summary, with would_create /
// would_skip populated and statuses reflecting WOULD_*.
func TestSummary_DryRunJSON_RoundTrips(t *testing.T) {
	s := apply.Summary{
		Bindings: []apply.BindingResult{
			{BindingID: "rb-aaa", Principal: "User:alice", Role: "DeveloperRead", Status: apply.StatusWouldCreate},
			{BindingID: "rb-bbb", Principal: "User:bob", Role: "DeveloperWrite", Status: apply.StatusWouldSkip},
		},
	}
	var buf bytes.Buffer
	if err := s.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var got apply.Summary
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("dry-run JSON did not round-trip: %v", err)
	}
	if got.Counts.WouldCreate != 1 || got.Counts.WouldSkip != 1 || got.Counts.Total != 2 {
		t.Errorf("counts: %+v", got.Counts)
	}
	if got.Bindings[0].Status != apply.StatusWouldCreate {
		t.Errorf("status: got %q want WOULD_CREATE", got.Bindings[0].Status)
	}
}

// TestDryRun_EmitsTextSummary exercises apply.DryRun end-to-end against
// a fake MDS and confirms the configured writer receives the dry-run
// summary one-liner.
func TestDryRun_EmitsTextSummary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rolebindings":{}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	mustWritePlanAndChecksum(t, planPath, twoBindingPlan())

	var buf bytes.Buffer
	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	if err := apply.DryRun(apply.Options{
		RunDir:        dir,
		PlanPath:      planPath,
		Client:        cl,
		SummaryWriter: &buf,
	}); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"apply (dry-run):", "2 would create", "0 would skip", "(2 total)"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run text summary missing %q:\n%s", want, out)
		}
	}
}

// TestRun_EmitsJSONSummary_OnStdoutWriter exercises apply.Run end-to-end
// against a fake MDS and asserts the JSON summary on the configured
// writer round-trips and reports the per-binding outcomes.
func TestRun_EmitsJSONSummary_OnStdoutWriter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/roles/") {
			w.WriteHeader(204)
			return
		}
		_, _ = w.Write([]byte(`{"rolebindings":{}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	mustWritePlanAndChecksum(t, planPath, twoBindingPlan())

	var buf bytes.Buffer
	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	if err := apply.Run(apply.Options{
		RunDir:        dir,
		PlanPath:      planPath,
		Client:        cl,
		SummaryWriter: &buf,
		SummaryFormat: apply.FormatJSON,
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	var sum apply.Summary
	if err := json.Unmarshal(buf.Bytes(), &sum); err != nil {
		t.Fatalf("JSON summary did not parse: %v\noutput:\n%s", err, buf.String())
	}
	if len(sum.Bindings) != 2 {
		t.Errorf("expected 2 binding results; got %d", len(sum.Bindings))
	}
	if sum.Counts.Created != 2 || sum.Counts.Total != 2 {
		t.Errorf("unexpected counts: %+v", sum.Counts)
	}
	for _, b := range sum.Bindings {
		if b.Status != apply.StatusCreated {
			t.Errorf("expected CREATED for %s; got %q", b.BindingID, b.Status)
		}
		if b.Principal == "" || b.Role == "" || b.BindingID == "" {
			t.Errorf("missing identity fields in binding result: %+v", b)
		}
	}
}

// TestSummary_JSON_ValidatesAgainstSchema asserts that apply.Summary's
// JSON output conforms to schemas/apply-summary.v1.json. Locks the
// envelope shape against drift; downstream CI consumers validate
// against the same schema.
func TestSummary_JSON_ValidatesAgainstSchema(t *testing.T) {
	s := apply.Summary{
		Bindings: []apply.BindingResult{
			{BindingID: "rb-0123456789ab", Principal: "User:alice", Role: "DeveloperRead", Status: apply.StatusCreated},
			{BindingID: "rb-cdef01234567", Principal: "User:bob", Role: "DeveloperWrite", Status: apply.StatusSkipExists},
			{BindingID: "rb-fedcba987654", Principal: "User:carol", Role: "ResourceOwner", Status: apply.StatusFailed, Error: "MDS 503"},
		},
	}
	var buf bytes.Buffer
	if err := s.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateApplySummary(buf.Bytes()); err != nil {
		t.Errorf("apply summary failed schema validation: %v\noutput:\n%s", err, buf.String())
	}
	// And the schema_version field is stamped at "1".
	var raw struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.SchemaVersion != "1" {
		t.Errorf("schema_version: got %q want %q", raw.SchemaVersion, "1")
	}
}

// TestSummary_DryRunJSON_ValidatesAgainstSchema asserts the dry-run
// envelope (WOULD_CREATE / WOULD_SKIP rows + would_* counts) also
// validates against the same schema.
func TestSummary_DryRunJSON_ValidatesAgainstSchema(t *testing.T) {
	s := apply.Summary{
		Bindings: []apply.BindingResult{
			{BindingID: "rb-0123456789ab", Principal: "User:alice", Role: "DeveloperRead", Status: apply.StatusWouldCreate},
			{BindingID: "rb-cdef01234567", Principal: "User:bob", Role: "DeveloperWrite", Status: apply.StatusWouldSkip},
		},
	}
	var buf bytes.Buffer
	if err := s.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateApplySummary(buf.Bytes()); err != nil {
		t.Errorf("dry-run summary failed schema validation: %v\noutput:\n%s", err, buf.String())
	}
}
