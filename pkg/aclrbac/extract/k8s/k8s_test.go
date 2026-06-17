// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package k8s

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// withDynForTest replaces the package-level dyn-builder so tests can
// inject a fake.Interface without touching kubeconfig. Returns a
// restore function to defer.
func withDynForTest(d dynamic.Interface, server string) func() {
	prevBuild := dynBuild
	dynBuild = func(_, _ string) (dynamic.Interface, string, error) { return d, server, nil }
	return func() { dynBuild = prevBuild }
}

func u(namespace, name string, gvkKind, gvkGroup, gvkVersion string, spec map[string]interface{}) *unstructured.Unstructured {
	o := &unstructured.Unstructured{}
	o.SetAPIVersion(gvkGroup + "/" + gvkVersion)
	o.SetKind(gvkKind)
	o.SetName(name)
	o.SetNamespace(namespace)
	o.Object["spec"] = spec
	return o
}

// TestExtract_PerListTimeout pins that each GVR List call gets its own fresh
// timeout context rather than sharing one cumulative budget. With a shared
// context every call sees the same deadline; with a per-call context the
// deadlines strictly advance as the loop progresses.
func TestExtract_PerListTimeout(t *testing.T) {
	var deadlines []time.Time
	prev := listFunc
	listFunc = func(ctx context.Context, _ dynamic.Interface, _ schema.GroupVersionResource, _ string, _ bool, _ string) ([]unstructured.Unstructured, error) {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Error("list call received a context with no deadline")
		}
		deadlines = append(deadlines, dl)
		time.Sleep(2 * time.Millisecond)
		return nil, nil
	}
	defer func() { listFunc = prev }()

	restore := withDynForTest(newFakeDyn(), "https://k8s.test:6443")
	defer restore()

	a, err := New(Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, _, _, _, err := a.Extract(); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(deadlines) < 2 {
		t.Fatalf("expected at least 2 list calls; got %d", len(deadlines))
	}
	for i := 1; i < len(deadlines); i++ {
		if !deadlines[i].After(deadlines[i-1]) {
			t.Errorf("list call %d shares the previous call's deadline — contexts are not per-call", i)
		}
	}
}

func TestNew_NoScopeRejected(t *testing.T) {
	_, err := New(Options{})
	if err == nil {
		t.Fatal("expected error when no scope given")
	}
}

func TestExtract_K8s_StrimziKafkaUser(t *testing.T) {
	user := u("kafka-ns", "alice", "KafkaUser", "kafka.strimzi.io", "v1beta2", map[string]interface{}{
		"authorization": map[string]interface{}{
			"type": "simple",
			"acls": []interface{}{
				map[string]interface{}{
					"resource": map[string]interface{}{
						"type": "topic", "name": "orders", "patternType": "literal",
					},
					"operations": []interface{}{"Read", "Describe"},
					"host":       "*",
					"type":       "allow",
				},
			},
		},
	})
	dyn := newFakeDyn(user)
	restore := withDynForTest(dyn, "https://k8s.test:6443")
	defer restore()

	a, err := New(Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	set, _, src, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 2 {
		t.Fatalf("got %d ACLs, want 2 (Read+Describe)", len(set.ACLs))
	}
	for _, r := range set.ACLs {
		if r.Principal != "User:alice" {
			t.Errorf("principal: got %q, want User:alice", r.Principal)
		}
		if r.ResourceType != types.ResourceTopic || r.ResourceName != "orders" {
			t.Errorf("resource: got %v/%q", r.ResourceType, r.ResourceName)
		}
	}
	if src.K8sServer != "https://k8s.test:6443" {
		t.Errorf("K8sServer: got %q", src.K8sServer)
	}
}

func TestExtract_K8s_CFKKafkaSuperusers(t *testing.T) {
	kafka := u("confluent", "kafka", "Kafka", "platform.confluent.io", "v1beta1", map[string]interface{}{
		"authorization": map[string]interface{}{
			"type":       "rbac",
			"superUsers": []interface{}{"User:admin", "User:ops"},
		},
	})
	dyn := newFakeDyn(kafka)
	restore := withDynForTest(dyn, "https://k8s.test:6443")
	defer restore()

	a, err := New(Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 2 {
		t.Fatalf("got %d ACLs, want 2 (two superUsers)", len(set.ACLs))
	}
	for _, r := range set.ACLs {
		if r.ResourceType != types.ResourceCluster || r.Operation != types.OpAll {
			t.Errorf("superuser row should be ALL on Cluster; got %+v", r)
		}
	}
}

func TestExtract_K8s_NamespaceScoped(t *testing.T) {
	a1 := u("teamA", "alice", "KafkaUser", "kafka.strimzi.io", "v1beta2", map[string]interface{}{
		"authorization": map[string]interface{}{
			"type": "simple",
			"acls": []interface{}{
				map[string]interface{}{
					"resource":   map[string]interface{}{"type": "topic", "name": "t1", "patternType": "literal"},
					"operations": []interface{}{"Read"},
					"host":       "*", "type": "allow",
				},
			},
		},
	})
	b1 := u("teamB", "bob", "KafkaUser", "kafka.strimzi.io", "v1beta2", map[string]interface{}{
		"authorization": map[string]interface{}{
			"type": "simple",
			"acls": []interface{}{
				map[string]interface{}{
					"resource":   map[string]interface{}{"type": "topic", "name": "t2", "patternType": "literal"},
					"operations": []interface{}{"Read"},
					"host":       "*", "type": "allow",
				},
			},
		},
	})
	dyn := newFakeDyn(a1, b1)
	restore := withDynForTest(dyn, "https://k8s.test:6443")
	defer restore()

	a, err := New(Options{Namespace: "teamA"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	set, _, src, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 1 {
		t.Fatalf("got %d ACLs, want 1 (only teamA's alice/t1)", len(set.ACLs))
	}
	if got := set.ACLs[0].ResourceName; got != "t1" {
		t.Errorf("wrong topic: %q", got)
	}
	if want := []string{"teamA"}; len(src.K8sNamespaces) != 1 || src.K8sNamespaces[0] != want[0] {
		t.Errorf("K8sNamespaces: got %v, want %v", src.K8sNamespaces, want)
	}
}

func TestExtract_K8s_StableIDs(t *testing.T) {
	user1 := u("ns", "alice", "KafkaUser", "kafka.strimzi.io", "v1beta2", map[string]interface{}{
		"authorization": map[string]interface{}{
			"type": "simple",
			"acls": []interface{}{
				map[string]interface{}{
					"resource":   map[string]interface{}{"type": "topic", "name": "orders", "patternType": "literal"},
					"operations": []interface{}{"Read", "Describe"},
					"host":       "*", "type": "allow",
				},
			},
		},
	})
	dyn := newFakeDyn(user1)
	restore := withDynForTest(dyn, "https://k8s.test:6443")
	defer restore()
	a, _ := New(Options{AllNamespaces: true})
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatal(err)
	}
	ids := []int{}
	for _, r := range set.ACLs {
		ids = append(ids, r.ID)
	}
	if len(ids) != 2 || ids[0] == 0 || ids[1] == 0 || ids[0] == ids[1] {
		t.Errorf("IDs should be unique non-zero; got %v", ids)
	}
}

func TestExtract_K8s_NoCRsInstalled(t *testing.T) {
	dyn := newFakeDyn()
	restore := withDynForTest(dyn, "https://k8s.test:6443")
	defer restore()
	a, _ := New(Options{AllNamespaces: true})
	set, _, _, log, err := a.Extract()
	if err != nil {
		t.Fatalf("empty cluster should not error; got %v", err)
	}
	if len(set.ACLs) != 0 {
		t.Errorf("got %d ACLs from empty cluster", len(set.ACLs))
	}
	_ = context.Background()
	_ = log
}
