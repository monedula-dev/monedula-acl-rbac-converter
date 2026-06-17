// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package script_test

import (
	"fmt"
	"io"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/script"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// genBindings returns n synthetic CREATE bindings on a single Kafka
// cluster. Used by emit benchmarks across all three emitters.
func genBindings(n int) []types.Binding {
	out := make([]types.Binding, n)
	for i := 0; i < n; i++ {
		out[i] = types.Binding{
			ID:        fmt.Sprintf("rb-%012x", i),
			Action:    types.ActionCreate,
			Principal: fmt.Sprintf("User:svc-%05d", i),
			Role:      "DeveloperRead",
			Scope:     types.Scope{KafkaCluster: "lkc-bench"},
			ResourcePatterns: []types.ResourcePattern{{
				ResourceType: types.ResourceTopic,
				Name:         fmt.Sprintf("topic-%06d", i),
				PatternType:  types.PatternLiteral,
			}},
			SourceACLIDs: []int{i * 2, i*2 + 1},
		}
	}
	return out
}

// BenchmarkEmit_Script_1000 measures the cost of rendering ~1k bindings.
// The script emitter is the simplest of the three (string concatenation,
// no JSON, no YAML); this is the floor for emit cost.
func BenchmarkEmit_Script_1000(b *testing.B) {
	benchEmitScript(b, 1000)
}

// BenchmarkEmit_Script_10000 — spec §12 scale target.
func BenchmarkEmit_Script_10000(b *testing.B) {
	benchEmitScript(b, 10000)
}

func benchEmitScript(b *testing.B, n int) {
	b.Helper()
	plan := types.Plan{SchemaVersion: "1", Bindings: genBindings(n)}
	em := script.New(script.Options{PlanPath: "bench/plan.json"})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := em.Emit(io.Discard, plan); err != nil {
			b.Fatal(err)
		}
	}
}
