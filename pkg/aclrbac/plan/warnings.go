// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan

import (
	"fmt"
	"sort"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// warningCollector accumulates warnings during planning. The Code field
// matches the values listed in spec §3.4 + §4.2 (e.g., "MTLS_DN_PASS_THROUGH",
// "HOST_RESTRICTED", "LONE_CREATE_ON_CLUSTER", "CONFLICTING_EXISTING_BINDING").
type warningCollector struct {
	entries []types.Warning
}

func (w *warningCollector) Add(code, detail string) {
	w.entries = append(w.entries, types.Warning{Code: code, Detail: detail})
}

func (w *warningCollector) AddF(code, format string, args ...interface{}) {
	w.Add(code, fmt.Sprintf(format, args...))
}

func (w *warningCollector) All() []types.Warning {
	out := make([]types.Warning, len(w.entries))
	copy(out, w.entries)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}
