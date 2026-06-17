// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package script

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestNormalizeOp pins the case-folding and alias branches of normalizeOp,
// the operation-name normaliser used when parsing kafka-acls argv. The
// canonical-case path is exercised by the script extractor's happy-path
// tests; this guards the inputs operators actually type — lowercase /
// mixed case and the underscore aliases (DESCRIBE_CONFIGS, ALTER_CONFIGS,
// CLUSTER_ACTION, IDEMPOTENT_WRITE) — which the higher-level tests don't.
func TestNormalizeOp(t *testing.T) {
	cases := []struct {
		in   string
		want types.Operation
	}{
		// case-folding to canonical form
		{"read", types.OpRead},
		{"READ", types.OpRead},
		{"Write", types.OpWrite},
		{"create", types.OpCreate},
		{"delete", types.OpDelete},
		{"alter", types.OpAlter},
		{"describe", types.OpDescribe},
		{"all", types.OpAll},

		// underscore vs concatenated aliases both fold to the canonical op
		{"cluster_action", types.OpClusterAction},
		{"CLUSTER_ACTION", types.OpClusterAction},
		{"describeconfigs", types.OpDescribeConfigs},
		{"DESCRIBE_CONFIGS", types.OpDescribeConfigs},
		{"alterconfigs", types.OpAlterConfigs},
		{"ALTER_CONFIGS", types.OpAlterConfigs},
		{"idempotentwrite", types.OpIdempotentWrite},
		{"IDEMPOTENT_WRITE", types.OpIdempotentWrite},
	}
	for _, tc := range cases {
		if got := normalizeOp(tc.in); got != tc.want {
			t.Errorf("normalizeOp(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNormalizeOp_UnknownPassesThrough: an operation the normaliser doesn't
// recognise is returned verbatim (as types.Operation) rather than dropped
// or coerced — downstream validation, not this function, decides whether
// it's legal, and silently rewriting it would hide a typo.
func TestNormalizeOp_UnknownPassesThrough(t *testing.T) {
	if got := normalizeOp("Frobnicate"); got != types.Operation("Frobnicate") {
		t.Errorf("normalizeOp(unknown) = %q, want verbatim passthrough", got)
	}
}
