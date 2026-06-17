// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package mdstest brings up a real Confluent cp-server (RBAC/MDS + OpenLDAP)
// via testcontainers so test suites can drive the production mds.Client and
// the full extract→plan→apply→verify pipeline against a real MDS — not an
// in-process fake. The stack also publishes a host-reachable PLAINTEXT broker
// listener so callers can create and live-extract ACLs from the same broker
// that backs MDS.
//
// The heavy, Docker-dependent harness lives in stack.go behind
// `//go:build integration || e2e`; this file keeps the package non-empty in
// the default (no-tag) build so `go build ./...` stays clean.
package mdstest
