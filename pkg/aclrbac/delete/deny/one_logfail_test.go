// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package deny_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/deny"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestOne_ExecFailureLogsFailAndReturnsError guards the FAIL path: when the
// live re-check clears a DENY for removal but the kafka-acls --remove exec
// itself fails, RunOne must (1) record a FAIL line in delete-deny.log and
// (2) return a non-nil error. The generated script runs under `set -e`, so
// a swallowed error here would let the loop march on past a removal that
// never actually happened — exactly the executed-vs-intended drift class
// TESTING.md §2.1 warns about. We drive the failure through the
// ExecKafkaACLs seam so no real broker is needed.
func TestOne_ExecFailureLogsFailAndReturnsError(t *testing.T) {
	// MDS reports no overlapping grant -> not allowed -> the code proceeds
	// to invoke kafka-acls --remove (which we make fail).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokFile := filepath.Join(dir, "mds.token")
	if err := os.WriteFile(tokFile, []byte("seeded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := common.WriteRuntimeEnv(dir, common.RuntimeEnv{
		BootstrapServers: "k:1",
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
			Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "secrets",
			PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny,
		}},
	}
	if err := rundir.WriteACLs(filepath.Join(dir, "acls.json"), aclSet); err != nil {
		t.Fatal(err)
	}
	writeMinimalPlan(t, dir) // acl_id=1 classified SAFE_TO_REMOVE

	err := deny.RunOne(deny.OneOptions{
		RunDir:        dir,
		ACLID:         1,
		EnvToken:      "tok",
		ExecKafkaACLs: func(_ []string) error { return &execErr{"kafka-acls: connection refused"} },
	})
	if err == nil {
		t.Fatal("expected a non-nil error when kafka-acls exec fails")
	}
	if !strings.Contains(err.Error(), "FAIL") {
		t.Errorf("returned error should signal FAIL; got: %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("returned error should carry the underlying exec failure; got: %v", err)
	}

	logBody, rerr := os.ReadFile(filepath.Join(dir, "delete-deny.log"))
	if rerr != nil {
		t.Fatalf("read delete-deny.log: %v", rerr)
	}
	log := string(logBody)
	if !strings.Contains(log, "FAIL acl_id=1") {
		t.Errorf("delete-deny.log must contain a FAIL line for acl_id=1; got:\n%s", log)
	}
	if !strings.Contains(log, "connection refused") {
		t.Errorf("FAIL line should record the exec error message; got:\n%s", log)
	}
	// A FAIL is not a SKIP and not an OK — the run did not succeed and was
	// not declined.
	if strings.Contains(log, "OK acl_id=1") {
		t.Errorf("a failed exec must not be logged as OK; got:\n%s", log)
	}
}

type execErr struct{ msg string }

func (e *execErr) Error() string { return e.msg }
