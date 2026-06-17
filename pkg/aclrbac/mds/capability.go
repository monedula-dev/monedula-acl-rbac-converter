// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds

import (
	"errors"
	"net/http"
)

// Capability indicates which MDS API set is available. Used to pick the
// effective-permission verification backend per spec §11.2.
type Capability string

const (
	CapabilityUnknown Capability = "unknown"
	CapabilityLookup  Capability = "lookup" // modern: /security/1.0/lookup/...
	CapabilityLegacy  Capability = "legacy" // older: enumerate bindings + role-resource matrix
)

// ProbeCapability sends a single GET to a modern-MDS endpoint and classifies
// the instance. It probes GET /security/1.0/roles (the role catalogue), which
// exists on modern RBAC-enabled MDS; the previously-probed
// /security/1.0/lookup/principals does not exist (404) on real MDS, so every
// modern instance was misclassified as legacy and effective-mode rows became
// EFFECTIVE_UNKNOWN across the board.
func ProbeCapability(cl *Client) (Capability, error) {
	resp, err := cl.Get("/security/1.0/roles")
	if err == nil {
		_ = resp.Body.Close()
		return CapabilityLookup, nil
	}
	var he *HTTPError
	if errors.As(err, &he) && he.StatusCode == http.StatusNotFound {
		return CapabilityLegacy, nil
	}
	return CapabilityUnknown, err
}
