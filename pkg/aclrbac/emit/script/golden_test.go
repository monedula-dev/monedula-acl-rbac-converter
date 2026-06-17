// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package script_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/script"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

var updateGolden = flag.Bool("update", false, "rewrite emit/script/testdata/golden.sh from current output")

// goldenSamplePlan returns the same plan all three emit-golden tests
// (script, cfk, mdscurl) use. Stable IDs, two bindings — one CREATE,
// one SKIP_EXISTS — so the golden also locks in the skip path.
func goldenSamplePlan() types.Plan {
	return types.Plan{
		SchemaVersion: "1",
		Bindings: []types.Binding{
			{
				ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
				Principal: "User:alice", Role: "DeveloperRead",
				Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
				ResourcePatterns: []types.ResourcePattern{{
					ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
				}},
				SourceACLIDs: []int{1, 2},
			},
			{
				ID: "rb-bbbbbbbbbbbb", Action: types.ActionSkipExists,
				Principal: "User:bob", Role: "DeveloperWrite",
				Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
				ResourcePatterns: []types.ResourcePattern{{
					ResourceType: types.ResourceTopic, Name: "events.", PatternType: types.PatternPrefixed,
				}},
				SourceACLIDs: []int{3, 4},
			},
		},
	}
}

func TestGoldenScript(t *testing.T) {
	plan := goldenSamplePlan()

	var buf bytes.Buffer
	em := script.New(script.Options{PlanPath: "<RUNDIR>/plan.json"})
	if _, err := em.Emit(&buf, plan); err != nil {
		t.Fatalf("emit: %v", err)
	}
	got := buf.Bytes()

	goldenPath := filepath.Join("testdata", "golden.sh")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", goldenPath)
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to seed)", goldenPath, err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("golden mismatch.\nwant:\n%s\n\ngot:\n%s\n\nRerun with -update if the change is intentional.", want, got)
	}
}
