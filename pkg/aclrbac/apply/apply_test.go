// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package apply_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/apply"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func samplePlan() types.Plan {
	return types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{{
			ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
			Principal: "User:alice", Role: "DeveloperRead",
			Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
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

func mustWritePlanAndChecksum(t *testing.T, planPath string, p types.Plan) {
	t.Helper()
	if err := rundir.WritePlan(planPath, p); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("write checksum: %v", err)
	}
}

func TestApply_RealConfirm(t *testing.T) {
	var created int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/roles/") {
			atomic.AddInt32(&created, 1)
			w.WriteHeader(204)
			return
		}
		_, _ = w.Write([]byte(`{"rolebindings":{}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	mustWritePlanAndChecksum(t, planPath, samplePlan())

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	if err := apply.Run(apply.Options{
		RunDir:   dir,
		PlanPath: planPath,
		Client:   cl,
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if atomic.LoadInt32(&created) != 1 {
		t.Errorf("expected 1 create call, got %d", created)
	}

	logData, _ := os.ReadFile(filepath.Join(dir, "apply.log"))
	if !strings.Contains(string(logData), "CREATE rb-aaaaaaaaaaaa") {
		t.Errorf("apply.log missing CREATE record:\n%s", logData)
	}
}

func TestApply_StaleChecksumRefused(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	mustWritePlanAndChecksum(t, planPath, samplePlan())

	p := samplePlan()
	p.GeneratedAt = "2026-05-22T10:00:00Z"
	_ = rundir.WritePlan(planPath, p)

	cl, _ := mds.NewClient(mds.Config{URL: "http://unused", Token: "t"})
	err := apply.Run(apply.Options{
		RunDir:   dir,
		PlanPath: planPath,
		Client:   cl,
	})
	if err == nil {
		t.Fatal("expected error for stale checksum")
	}
}

func TestApply_DryRunWritesWouldApplyLog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rolebindings":{}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	mustWritePlanAndChecksum(t, planPath, samplePlan())

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	if err := apply.DryRun(apply.Options{
		RunDir:   dir,
		PlanPath: planPath,
		Client:   cl,
	}); err != nil {
		t.Fatalf("dryrun: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "would-apply.log")); err != nil {
		t.Errorf("would-apply.log not written: %v", err)
	}
}

// TestApply_DryRunLogsTheRequestApplySends pins would-apply.log to the exact
// request a real apply POSTs: the percent-escaped path and the camelCase MDS
// body with hyphenated cluster keys. Logging the plan.json (snake_case) shape
// instead misleads anyone replaying the log — MDS rejects it with HTTP 400.
func TestApply_DryRunLogsTheRequestApplySends(t *testing.T) {
	const (
		wantPath = "/security/1.0/principals/User:CN=alice%2COU=eng/roles/DeveloperRead/bindings"
		wantBody = `{"scope":{"clusters":{"kafka-cluster":"lkc-kafka01"}},"resourcePatterns":[{"resourceType":"Topic","name":"orders","patternType":"LITERAL"}]}`
	)
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/bindings") {
			body, _ := io.ReadAll(r.Body)
			gotPath, gotBody = r.URL.EscapedPath(), string(body)
			w.WriteHeader(204)
			return
		}
		_, _ = w.Write([]byte(`{"rolebindings":{}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	p := samplePlan()
	p.Bindings[0].Principal = "User:CN=alice,OU=eng"
	mustWritePlanAndChecksum(t, planPath, p)
	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	opts := apply.Options{RunDir: dir, PlanPath: planPath, Client: cl}

	if err := apply.DryRun(opts); err != nil {
		t.Fatalf("dryrun: %v", err)
	}
	logData, err := os.ReadFile(filepath.Join(dir, "would-apply.log"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "WOULD POST " + wantPath + "\nBODY " + wantBody + "\n"; !strings.Contains(string(logData), want) {
		t.Errorf("would-apply.log does not show the real request\nwant:\n%s\ngot:\n%s", want, logData)
	}

	if err := apply.Run(opts); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if gotPath != wantPath || gotBody != wantBody {
		t.Errorf("apply sent a different request than dry-run logged\npath: %s\nbody: %s", gotPath, gotBody)
	}
}

func twoBindingPlan() types.Plan {
	return types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{
			{
				ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
				Principal: "User:alice", Role: "DeveloperRead",
				Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
				ResourcePatterns: []types.ResourcePattern{{
					ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
				}},
				SourceACLIDs: []int{1},
			},
			{
				ID: "rb-bbbbbbbbbbbb", Action: types.ActionCreate,
				Principal: "User:bob", Role: "DeveloperRead",
				Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
				ResourcePatterns: []types.ResourcePattern{{
					ResourceType: types.ResourceTopic, Name: "payments", PatternType: types.PatternLiteral,
				}},
				SourceACLIDs: []int{2},
			},
		},
		Unmapped:     []types.UnmappedEntry{},
		Rejected:     []types.RejectedEntry{},
		Warnings:     []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{},
	}
}

func TestApply_Progress_PrintsPerBinding(t *testing.T) {
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
		RunDir:   dir,
		PlanPath: planPath,
		Client:   cl,
		Progress: apply.NewProgressWriter(&buf, true),
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	lines := strings.Count(buf.String(), "\n")
	if lines < 2 {
		t.Errorf("expected at least 2 per-binding progress lines; got %q", buf.String())
	}
}

func TestApply_Progress_DisabledByDefault(t *testing.T) {
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
	mustWritePlanAndChecksum(t, planPath, samplePlan())

	var buf bytes.Buffer
	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	if err := apply.Run(apply.Options{
		RunDir:   dir,
		PlanPath: planPath,
		Client:   cl,
		Progress: apply.NewProgressWriter(&buf, false),
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no progress output when disabled; got %q", buf.String())
	}
}
