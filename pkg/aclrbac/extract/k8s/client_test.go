// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package k8s

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildRestConfig_MissingFileReturnsError(t *testing.T) {
	_, _, err := buildRestConfig("/nonexistent/kubeconfig", "")
	if err == nil {
		t.Fatal("expected error on missing kubeconfig path")
	}
}

func TestBuildRestConfig_ValidConfigReturnsServerURL(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "config")
	const sample = `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://example.test:6443
    insecure-skip-tls-verify: true
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
users:
- name: test
  user:
    token: dummy
`
	if err := os.WriteFile(kc, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, server, err := buildRestConfig(kc, "")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfg == nil {
		t.Fatal("rest.Config is nil")
	}
	if server != "https://example.test:6443" {
		t.Errorf("server: got %q, want https://example.test:6443", server)
	}
}

func TestBuildRestConfig_ContextOverride(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "config")
	const sample = `apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster:
    server: https://prod.test:6443
    insecure-skip-tls-verify: true
- name: dev
  cluster:
    server: https://dev.test:6443
    insecure-skip-tls-verify: true
contexts:
- name: prod
  context: {cluster: prod, user: alice}
- name: dev
  context: {cluster: dev, user: alice}
current-context: prod
users:
- name: alice
  user:
    token: dummy
`
	if err := os.WriteFile(kc, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	// Without override: current-context (prod).
	_, server, err := buildRestConfig(kc, "")
	if err != nil || server != "https://prod.test:6443" {
		t.Errorf("default context: server=%q err=%v", server, err)
	}
	// With override: dev.
	_, server, err = buildRestConfig(kc, "dev")
	if err != nil || server != "https://dev.test:6443" {
		t.Errorf("dev context: server=%q err=%v", server, err)
	}
}
