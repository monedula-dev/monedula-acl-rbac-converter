// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cfk_test

import (
	"fmt"
	"io"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/cfk"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// genBindings is duplicated across the three emit packages because each
// is in its own test package; sharing would require a fixtures package.
// The cost (a couple of dozen lines per file) is lower than the
// dependency cost.
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

func BenchmarkEmit_CFK_1000(b *testing.B) { benchEmitCFK(b, 1000) }

// BenchmarkEmit_CFK_10000 — spec §12 scale target. YAML emission is
// the heaviest of the three formats; this catches regressions that
// turn it accidentally quadratic.
func BenchmarkEmit_CFK_10000(b *testing.B) { benchEmitCFK(b, 10000) }

func benchEmitCFK(b *testing.B, n int) {
	b.Helper()
	plan := types.Plan{SchemaVersion: "1", Bindings: genBindings(n)}
	em := cfk.New(cfk.Options{Namespace: "confluent"})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := em.Emit(io.Discard, plan); err != nil {
			b.Fatal(err)
		}
	}
}
