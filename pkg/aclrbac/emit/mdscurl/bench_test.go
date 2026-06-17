// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mdscurl_test

import (
	"fmt"
	"io"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/mdscurl"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

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

func BenchmarkEmit_MDSCurl_1000(b *testing.B) { benchEmitMDSCurl(b, 1000) }

// BenchmarkEmit_MDSCurl_10000 — spec §12 scale target. The mds-curl
// emitter does JSON-marshal-per-binding; a regression that adds
// reflection or unnecessary allocations shows up here.
func BenchmarkEmit_MDSCurl_10000(b *testing.B) { benchEmitMDSCurl(b, 10000) }

func benchEmitMDSCurl(b *testing.B, n int) {
	b.Helper()
	plan := types.Plan{SchemaVersion: "1", Bindings: genBindings(n)}
	em := mdscurl.New(mdscurl.Options{PlanPath: "bench/plan.json"})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := em.Emit(io.Discard, plan); err != nil {
			b.Fatal(err)
		}
	}
}
