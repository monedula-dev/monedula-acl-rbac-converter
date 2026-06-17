// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package verify_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
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
			SourceACLIDs: []int{1, 2},
		}},
		Unmapped:     []types.UnmappedEntry{},
		Rejected:     []types.RejectedEntry{},
		Warnings:     []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{},
	}
}

func TestVerify_BindingsExistOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rolebindings":{"User:alice":{"DeveloperRead":[{"resourceType":"Topic","name":"orders","patternType":"LITERAL"}]}}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, samplePlan()); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	res, err := verify.Run(verify.Options{
		RunDir:   dir,
		PlanPath: planPath,
		Client:   cl,
		Mode:     verify.ModeBindingsExist,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res) != 1 || res[0].Status != verify.StatusBindingExists {
		t.Errorf("got %+v", res)
	}
}

func TestVerify_EffectiveOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/security/1.0/roles": // capability probe
			_, _ = w.Write([]byte(`[]`))
		case strings.HasPrefix(r.URL.Path, "/security/1.0/roles/"): // role definition
			_, _ = w.Write([]byte(`{"name":"DeveloperRead","accessPolicy":{"allowedOperations":[{"resourceType":"Topic","operations":["Read","Describe"]}]}}`))
		default: // POST /lookup/principal/{p}/resources
			_, _ = w.Write([]byte(`{"User:alice":{"DeveloperRead":[{"resourceType":"Topic","name":"orders","patternType":"LITERAL"}]}}`))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, samplePlan()); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	res, err := verify.Run(verify.Options{
		RunDir:    dir,
		PlanPath:  planPath,
		Client:    cl,
		Mode:      verify.ModeEffective,
		SourceOps: map[int]types.Operation{1: types.OpRead, 2: types.OpDescribe},
		SourceResources: map[int]verify.ResourceRef{
			1: {Type: types.ResourceTopic, Name: "orders", Pattern: types.PatternLiteral},
			2: {Type: types.ResourceTopic, Name: "orders", Pattern: types.PatternLiteral},
		},
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d results, want 2 (one per source ACL)", len(res))
	}
	for _, r := range res {
		if r.Status != verify.StatusEffectiveOK {
			t.Errorf("expected EFFECTIVE_OK; got %+v", r)
		}
	}
}

// TestVerify_AcceptUnknownDowngradesEffectiveUnknown locks in the
// --accept-unknown-verify wiring (README "Step 4"). Pre-fix the
// Options.AcceptUnknown field was a dead end — set by the CLI,
// declared on the struct, never consumed inside Run. The downgrade
// here is what makes delete-acls accept the row as eligible.
func TestVerify_AcceptUnknownDowngradesEffectiveUnknown(t *testing.T) {
	// MDS that fails the lookup endpoint, so every source ACL ends up
	// EFFECTIVE_UNKNOWN.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/security/1.0/roles" {
			// capability probe succeeds (modern MDS)
			_, _ = w.Write([]byte(`[]`))
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, samplePlan()); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	baseOpts := verify.Options{
		RunDir:    dir,
		PlanPath:  planPath,
		Client:    cl,
		Mode:      verify.ModeEffective,
		SourceOps: map[int]types.Operation{1: types.OpRead, 2: types.OpDescribe},
		SourceResources: map[int]verify.ResourceRef{
			1: {Type: types.ResourceTopic, Name: "orders", Pattern: types.PatternLiteral},
			2: {Type: types.ResourceTopic, Name: "orders", Pattern: types.PatternLiteral},
		},
	}

	// Without --accept-unknown-verify: every row is EFFECTIVE_UNKNOWN.
	res, err := verify.Run(baseOpts)
	if err != nil {
		t.Fatalf("verify (default): %v", err)
	}
	for _, r := range res {
		if r.Status != verify.StatusEffectiveUnknown {
			t.Errorf("default: want EFFECTIVE_UNKNOWN; got %+v", r)
		}
	}

	// With --accept-unknown-verify: the same rows are downgraded to
	// EFFECTIVE_OK; the Detail field records the downgrade.
	acceptOpts := baseOpts
	acceptOpts.AcceptUnknown = true
	res2, err := verify.Run(acceptOpts)
	if err != nil {
		t.Fatalf("verify (accept-unknown): %v", err)
	}
	for _, r := range res2 {
		if r.Status != verify.StatusEffectiveOK {
			t.Errorf("accept-unknown: want EFFECTIVE_OK; got %+v", r)
		}
		if !strings.Contains(r.Detail, "downgraded by --accept-unknown-verify") {
			t.Errorf("accept-unknown: Detail must mark downgrade; got %q", r.Detail)
		}
	}
}

// TestVerify_ProbeFailureNotMaskedByAcceptUnknown is the B5 regression
// guard: when the MDS capability probe itself fails (here a 502, i.e. MDS
// is unreachable/erroring — distinct from a 404 "endpoint not supported"),
// verify must error out rather than mark every row EFFECTIVE_UNKNOWN and
// let --accept-unknown-verify silently downgrade the whole run to OK.
func TestVerify_ProbeFailureNotMaskedByAcceptUnknown(t *testing.T) {
	// Every endpoint 502s, including the capability probe.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, samplePlan()); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	_, err := verify.Run(verify.Options{
		RunDir:   dir,
		PlanPath: planPath,
		Client:   cl,
		Mode:     verify.ModeEffective,
		// Operator opted into accepting UNKNOWN — but a dead MDS must
		// still fail loudly, not silently pass.
		AcceptUnknown: true,
		SourceOps:     map[int]types.Operation{1: types.OpRead, 2: types.OpDescribe},
		SourceResources: map[int]verify.ResourceRef{
			1: {Type: types.ResourceTopic, Name: "orders", Pattern: types.PatternLiteral},
			2: {Type: types.ResourceTopic, Name: "orders", Pattern: types.PatternLiteral},
		},
	})
	if err == nil {
		t.Fatal("expected error when MDS probe fails; --accept-unknown-verify must not mask an MDS outage")
	}
	if !strings.Contains(err.Error(), "capability probe failed") {
		t.Errorf("error should explain the probe failure; got: %v", err)
	}
}

// TestVerify_BindingsExist_ResourcePatternsMustMatch pins the
// stricter matcher: an existing binding with the same principal /
// role / scope but a different resource pattern set must produce
// BINDING_MISSING rather than BINDING_EXISTS. Pre-fix the matcher
// ignored patterns entirely, so an unrelated binding falsely vouched
// for the planned one — and delete-acls then accepted the unrelated
// source ACL as eligible for deletion.
func TestVerify_BindingsExist_ResourcePatternsMustMatch(t *testing.T) {
	// Existing binding covers Topic:payments LITERAL, but the plan asks
	// about Topic:orders LITERAL. Pre-fix, matched() said "exists".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rolebindings":{"User:alice":{"DeveloperRead":[{"resourceType":"Topic","name":"payments","patternType":"LITERAL"}]}}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, samplePlan()); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	res, err := verify.Run(verify.Options{
		RunDir:   dir,
		PlanPath: planPath,
		Client:   cl,
		Mode:     verify.ModeBindingsExist,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res) != 1 || res[0].Status != verify.StatusBindingMissing {
		t.Errorf("got %+v; want one BINDING_MISSING row (patterns differ)", res)
	}
}

// TestVerify_BindingsExist_AggregatedBinding pins containment matching: MDS
// returns ONE binding per (principal, role, scope) whose ResourcePatterns is
// the union of every grant, while the plan emits one binding per source ACL.
// A principal that reads a topic AND its consumer group (both DeveloperRead)
// is stored by MDS as a single 2-pattern binding; the planned 1-pattern
// binding must still verify as BINDING_EXISTS. Exact set-equality (the pre-fix
// matcher) reported it MISSING even though the pattern is installed.
func TestVerify_BindingsExist_AggregatedBinding(t *testing.T) {
	// MDS aggregates Topic:orders (the planned pattern) together with an extra
	// Group:orders-consumers grant the same principal holds for the same role.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rolebindings":{"User:alice":{"DeveloperRead":[` +
			`{"resourceType":"Topic","name":"orders","patternType":"LITERAL"},` +
			`{"resourceType":"Group","name":"orders-consumers","patternType":"LITERAL"}` +
			`]}}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, samplePlan()); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	res, err := verify.Run(verify.Options{
		RunDir:   dir,
		PlanPath: planPath,
		Client:   cl,
		Mode:     verify.ModeBindingsExist,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res) != 1 || res[0].Status != verify.StatusBindingExists {
		t.Errorf("got %+v; want one BINDING_EXISTS row (planned pattern is a subset of the aggregated binding)", res)
	}
}

// manyBindingPlan builds a plan with n bindings, each a distinct principal
// so bindings-exist issues one ListBindings per binding (n MDS calls).
func manyBindingPlan(n int) types.Plan {
	p := types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Unmapped:      []types.UnmappedEntry{},
		Rejected:      []types.RejectedEntry{},
		Warnings:      []types.Warning{},
		DenyAnalysis:  []types.DenyAnalysisEntry{},
	}
	for i := 0; i < n; i++ {
		p.Bindings = append(p.Bindings, types.Binding{
			ID: fmt.Sprintf("rb-%012d", i), Action: types.ActionCreate,
			Principal: fmt.Sprintf("User:u%d", i), Role: "DeveloperRead",
			Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
			ResourcePatterns: []types.ResourcePattern{{
				ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
			}},
			SourceACLIDs: []int{i + 1},
		})
	}
	return p
}

// TestVerify_BindingsExist_RunsInParallel asserts the worker pool actually
// runs --verify-parallelism MDS calls concurrently. The httptest handler
// blocks each request on a barrier that only releases once `want`
// requests are in flight simultaneously; if verify were serial (or the
// flag inert), the barrier would never fill and the test would deadlock
// (caught by the overall test timeout). It also records peak concurrency
// and asserts it reached the configured parallelism.
func TestVerify_BindingsExist_RunsInParallel(t *testing.T) {
	const nBindings = 20
	const want = 8 // matches Parallelism below

	var (
		mu       sync.Mutex
		inFlight int
		peak     int
		barrier  = make(chan struct{})
		reached  int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		atReached := inFlight >= want
		mu.Unlock()

		if atReached {
			// Release everyone once `want` requests pile up. Use a
			// CAS-guarded close so only the first goroutine closes.
			if atomic.CompareAndSwapInt32(&reached, 0, 1) {
				close(barrier)
			}
		}
		<-barrier

		mu.Lock()
		inFlight--
		mu.Unlock()
		_, _ = w.Write([]byte(`{"rolebindings":{}}`)) // no matching binding -> BINDING_MISSING (fine)
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, manyBindingPlan(nBindings)); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	res, err := verify.Run(verify.Options{
		RunDir:      dir,
		PlanPath:    planPath,
		Client:      cl,
		Mode:        verify.ModeBindingsExist,
		Parallelism: want,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res) != nBindings {
		t.Fatalf("got %d results, want %d", len(res), nBindings)
	}
	mu.Lock()
	gotPeak := peak
	mu.Unlock()
	if gotPeak < want {
		t.Errorf("peak concurrency %d, want at least %d (worker pool not parallelising)", gotPeak, want)
	}

	// Result ordering must match plan order despite concurrent execution.
	for i, r := range res {
		wantID := fmt.Sprintf("rb-%012d", i)
		if r.BindingID != wantID {
			t.Errorf("result[%d].BindingID = %q, want %q (ordering not preserved)", i, r.BindingID, wantID)
		}
	}
}

// TestVerify_BindingsExist_Parallelism1Serializes is the other half of the
// --verify-parallelism observable-effect contract (see the cli package
// anti-dead-flag doc): RunsInParallel proves parallelism=N reaches N
// concurrent calls; this proves parallelism=1 actually THROTTLES to one
// in-flight MDS call at a time. Without this direction a flag that ignored
// its value (always running at the default fan-out) would still pass the
// "reaches N" test. The handler holds each request briefly so overlapping
// calls would be observed if the semaphore were not size-1.
func TestVerify_BindingsExist_Parallelism1Serializes(t *testing.T) {
	const nBindings = 12

	var (
		mu       sync.Mutex
		inFlight int
		peak     int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		mu.Unlock()

		// Hold the request long enough that, were verify issuing calls
		// concurrently, a second goroutine would enter and bump inFlight.
		time.Sleep(5 * time.Millisecond)

		mu.Lock()
		inFlight--
		mu.Unlock()
		_, _ = w.Write([]byte(`{"rolebindings":{}}`)) // no match -> BINDING_MISSING (fine)
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, manyBindingPlan(nBindings)); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	res, err := verify.Run(verify.Options{
		RunDir:      dir,
		PlanPath:    planPath,
		Client:      cl,
		Mode:        verify.ModeBindingsExist,
		Parallelism: 1, // the flag under test
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res) != nBindings {
		t.Fatalf("got %d results, want %d", len(res), nBindings)
	}
	mu.Lock()
	gotPeak := peak
	mu.Unlock()
	if gotPeak != 1 {
		t.Errorf("peak concurrency %d with --verify-parallelism=1; want exactly 1 (flag did not serialize)", gotPeak)
	}
}

func TestVerify_OutPath_OperatorOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rolebindings":{"User:alice":{"DeveloperRead":[{"resourceType":"Topic","name":"orders","patternType":"LITERAL"}]}}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, samplePlan()); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}

	outDir := t.TempDir()
	customOut := filepath.Join(outDir, "custom.json")

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	if _, err := verify.Run(verify.Options{
		RunDir:   dir,
		PlanPath: planPath,
		Client:   cl,
		Mode:     verify.ModeBindingsExist,
		OutPath:  customOut,
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// OutPath was honoured: custom.json exists with content.
	if _, err := os.Stat(customOut); err != nil {
		t.Fatalf("OutPath not honoured; custom.json missing: %v", err)
	}
	// Default <runDir>/verify.json must NOT have been written.
	if _, err := os.Stat(filepath.Join(dir, "verify.json")); !os.IsNotExist(err) {
		t.Errorf("default verify.json should not exist when OutPath set; got err=%v", err)
	}
}
