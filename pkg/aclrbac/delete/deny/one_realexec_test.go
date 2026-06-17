// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package deny_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/deny"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestMain doubles this test binary as a fake `kafka-acls`. When
// realExec shells out via MONEDULA_KAFKA_ACLS_BIN pointed at os.Args[0],
// the re-exec'd process sees MONEDULA_TEST_ACLS_ARGS_FILE set, writes the
// argv it received to that file, and exits 0 — standing in for kafka-acls
// without a real broker or binary. Without the env var it runs the test
// suite normally.
//
// This is what lets a test exercise delete-deny-one's REAL exec path
// (one.go::realExec), which the ExecKafkaACLs fake seam used by every
// other test in this package never touches.
func TestMain(m *testing.M) {
	if out := os.Getenv("MONEDULA_TEST_ACLS_ARGS_FILE"); out != "" {
		_ = os.WriteFile(out, []byte(strings.Join(os.Args[1:], " ")), 0o600)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestOne_RealExecPath_PrefixedDenyAndAuth closes the structural gap the
// review flagged: every other delete-deny-one test injects ExecKafkaACLs
// (a fake), so the actual realExec → kafka-acls hand-off — and the argv it
// produces — was never executed. This test drives RunOne with
// ExecKafkaACLs nil (the production path), redirects kafka-acls to this
// test binary via MONEDULA_KAFKA_ACLS_BIN, and asserts on the argv the
// real exec actually delivered.
//
// It would have caught both B1 (a PREFIXED DENY emitted with no
// --resource-pattern-type, silently no-op'ing) and the delete-deny-one
// "calls MDS unauthenticated" bug (no Bearer token), through the real
// code path rather than a stand-in.
func TestOne_RealExecPath_PrefixedDenyAndAuth(t *testing.T) {
	var (
		mu       sync.Mutex
		lastAuth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastAuth = r.Header.Get("Authorization")
		mu.Unlock()
		// No matching resources -> not allowed -> SAFE_TO_REMOVE path,
		// so RunOne proceeds to the kafka-acls --remove exec.
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokFile := filepath.Join(dir, "mds.token")
	if err := os.WriteFile(tokFile, []byte("seeded-bearer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "broker.internal:9092",
		MDSURL:           srv.URL,
		MDSTokenFile:     tokFile,
		AuthToken:        "tok",
	}); err != nil {
		t.Fatal(err)
	}
	aclSet := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{{
			ID: 1, Principal: "User:eve", Host: "*",
			Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secret-",
			PatternType: types.PatternPrefixed, PermissionType: types.PermissionDeny,
		}},
	}
	if err := rundir.WriteACLs(filepath.Join(dir, "acls.json"), aclSet); err != nil {
		t.Fatal(err)
	}
	writeMinimalPlan(t, dir)

	// Point realExec at this test binary acting as the kafka-acls stub.
	argsFile := filepath.Join(dir, "kafka-acls-argv.txt")
	t.Setenv("MONEDULA_KAFKA_ACLS_BIN", os.Args[0])
	t.Setenv("MONEDULA_TEST_ACLS_ARGS_FILE", argsFile)

	// ExecKafkaACLs intentionally nil -> RunOne uses realExec (production).
	if err := deny.RunOne(deny.OneOptions{
		RunDir:   dir,
		ACLID:    1,
		EnvToken: "tok",
	}); err != nil {
		t.Fatalf("RunOne (real exec path): %v", err)
	}

	// The stub recorded the exact argv kafka-acls received.
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("stub kafka-acls did not record argv (was realExec invoked?): %v", err)
	}
	argv := string(raw)
	for _, want := range []string{
		"--remove",
		"--deny-principal User:eve",
		"--operation Read",
		"--resource-pattern-type prefixed", // B1: must not be omitted for PREFIXED
		"--topic secret-",
		"--bootstrap-server broker.internal:9092",
	} {
		if !strings.Contains(argv, want) {
			t.Errorf("real kafka-acls argv missing %q\nfull argv: %s", want, argv)
		}
	}

	// The live re-check must have authenticated: a Bearer token built from
	// the runtime.env token file. Empty/absent auth is the unauth bug.
	mu.Lock()
	gotAuth := lastAuth
	mu.Unlock()
	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Errorf("MDS live re-check was not authenticated; Authorization header = %q", gotAuth)
	}

	// And the outcome was logged OK.
	logBody, _ := os.ReadFile(filepath.Join(dir, "delete-deny.log"))
	if !strings.Contains(string(logBody), "OK acl_id=1") {
		t.Errorf("expected 'OK acl_id=1' in delete-deny.log; got:\n%s", logBody)
	}
}
