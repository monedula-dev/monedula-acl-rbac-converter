// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/live"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// fakeACL describes one ACL row the canned broker should return.
// It's the trimmed-down test fixture format.
type fakeACL struct {
	principal string
	host      string
	op        kmsg.ACLOperation
	resType   kmsg.ACLResourceType
	resName   string
	pattern   kmsg.ACLResourcePatternType
	perm      kmsg.ACLPermissionType
}

// newFakeWithACLs spins up a kfake cluster and installs a Control hook
// that intercepts DescribeACLs requests, returning the given canned rows.
// Filter semantics are simulated to mirror what a real broker would
// return for a Principal filter (other dimensions return all rows; the
// production code only uses a Principal filter at network level today).
//
// The closeFn returned must be deferred by the caller.
func newFakeWithACLs(t *testing.T, rows []fakeACL) ([]string, func()) {
	t.Helper()
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1))
	if err != nil {
		t.Fatalf("kfake: %v", err)
	}

	cluster.ControlKey(int16(kmsg.DescribeACLs), func(req kmsg.Request) (kmsg.Response, error, bool) {
		cluster.KeepControl()

		dr, ok := req.(*kmsg.DescribeACLsRequest)
		if !ok {
			return nil, nil, false
		}

		// Apply the principal filter at the simulated broker.
		// nil or "" Principal == "match any".
		wantPrincipal := ""
		if dr.Principal != nil {
			wantPrincipal = *dr.Principal
		}

		// Group matching rows by (resourceType, resourceName, patternType)
		// to mirror the DescribeACLsResponseResource shape Kafka uses.
		type rkey struct {
			rt kmsg.ACLResourceType
			rn string
			pt kmsg.ACLResourcePatternType
		}
		bucket := map[rkey][]kmsg.DescribeACLsResponseResourceACL{}
		order := []rkey{}
		for _, r := range rows {
			if wantPrincipal != "" && r.principal != wantPrincipal {
				continue
			}
			k := rkey{r.resType, r.resName, r.pattern}
			if _, seen := bucket[k]; !seen {
				order = append(order, k)
			}
			bucket[k] = append(bucket[k], kmsg.DescribeACLsResponseResourceACL{
				Principal:      r.principal,
				Host:           r.host,
				Operation:      r.op,
				PermissionType: r.perm,
			})
		}

		resp := &kmsg.DescribeACLsResponse{}
		resp.Default()
		resp.Version = dr.Version
		for _, k := range order {
			resp.Resources = append(resp.Resources, kmsg.DescribeACLsResponseResource{
				ResourceType:        k.rt,
				ResourceName:        k.rn,
				ResourcePatternType: k.pt,
				ACLs:                bucket[k],
			})
		}
		return resp, nil, true
	})

	return cluster.ListenAddrs(), cluster.Close
}

func TestExtract_LiveCluster_NoACLs(t *testing.T) {
	addrs, closeFn := newFakeWithACLs(t, nil)
	defer closeFn()

	a, err := live.New(addrs, "", nil, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	set, _, src, log, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 0 {
		t.Errorf("expected 0 ACLs on empty cluster; got %d", len(set.ACLs))
	}
	if src.Kind != "live" {
		t.Errorf("Kind: got %q, want live", src.Kind)
	}
	if src.LiveBootstrapServers == "" {
		t.Errorf("LiveBootstrapServers must be populated for audit")
	}
	if log == nil {
		t.Errorf("Logger must be non-nil")
	}
}

func TestExtract_LiveCluster_SeedAndDescribe(t *testing.T) {
	addrs, closeFn := newFakeWithACLs(t, []fakeACL{
		{
			principal: "User:alice", host: "*",
			op:      kmsg.ACLOperationRead,
			resType: kmsg.ACLResourceTypeTopic, resName: "orders",
			pattern: kmsg.ACLResourcePatternTypeLiteral,
			perm:    kmsg.ACLPermissionTypeAllow,
		},
		{
			principal: "User:alice", host: "*",
			op:      kmsg.ACLOperationDescribe,
			resType: kmsg.ACLResourceTypeTopic, resName: "orders",
			pattern: kmsg.ACLResourcePatternTypeLiteral,
			perm:    kmsg.ACLPermissionTypeAllow,
		},
	})
	defer closeFn()

	a, err := live.New(addrs, "", nil, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 2 {
		t.Fatalf("got %d ACLs, want 2 (Read + Describe)", len(set.ACLs))
	}

	// Determinism: sort rows by Operation so the assertions below are
	// stable. (Extract output should already be ordered by id ascending,
	// which is roughly the order kafka returned them, but the test sorts
	// defensively in case of multi-broker reorderings.)
	sort.Slice(set.ACLs, func(i, j int) bool { return set.ACLs[i].Operation < set.ACLs[j].Operation })

	for _, r := range set.ACLs {
		if r.Principal != "User:alice" {
			t.Errorf("principal: got %q, want User:alice", r.Principal)
		}
		if r.ResourceType != types.ResourceTopic {
			t.Errorf("resource type: got %q, want Topic", r.ResourceType)
		}
		if r.ResourceName != "orders" {
			t.Errorf("resource name: got %q, want orders", r.ResourceName)
		}
		if r.PatternType != types.PatternLiteral {
			t.Errorf("pattern: got %q, want LITERAL", r.PatternType)
		}
		if r.PermissionType != types.PermissionAllow {
			t.Errorf("permission: got %q, want Allow", r.PermissionType)
		}
	}

	// IDs assigned by the adapter: 1..N in observed order, 1-indexed.
	ids := map[int]bool{}
	for _, r := range set.ACLs {
		ids[r.ID] = true
	}
	if !ids[1] || !ids[2] {
		t.Errorf("expected IDs {1,2}; got %v", ids)
	}
}

func TestExtract_LiveCluster_PrincipalFilter(t *testing.T) {
	addrs, closeFn := newFakeWithACLs(t, []fakeACL{
		{
			principal: "User:alice", host: "*",
			op:      kmsg.ACLOperationRead,
			resType: kmsg.ACLResourceTypeTopic, resName: "orders",
			pattern: kmsg.ACLResourcePatternTypeLiteral,
			perm:    kmsg.ACLPermissionTypeAllow,
		},
		{
			principal: "User:bob", host: "*",
			op:      kmsg.ACLOperationRead,
			resType: kmsg.ACLResourceTypeTopic, resName: "orders",
			pattern: kmsg.ACLResourcePatternTypeLiteral,
			perm:    kmsg.ACLPermissionTypeAllow,
		},
	})
	defer closeFn()

	a, err := live.New(addrs, "", []string{"User:alice"}, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) == 0 {
		t.Fatalf("principal filter returned 0 ACLs; expected at least alice's")
	}
	for _, r := range set.ACLs {
		if r.Principal != "User:alice" {
			t.Errorf("principal filter not applied; saw %q", r.Principal)
		}
	}
}

// newFakeSecurityDisabled spins up a kfake cluster whose DescribeACLs
// always responds with the SECURITY_DISABLED error code (54), mirroring a
// broker that has no authorizer configured (ACLs not enabled).
func newFakeSecurityDisabled(t *testing.T) ([]string, func()) {
	t.Helper()
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1))
	if err != nil {
		t.Fatalf("kfake: %v", err)
	}

	cluster.ControlKey(int16(kmsg.DescribeACLs), func(req kmsg.Request) (kmsg.Response, error, bool) {
		cluster.KeepControl()

		dr, ok := req.(*kmsg.DescribeACLsRequest)
		if !ok {
			return nil, nil, false
		}
		resp := &kmsg.DescribeACLsResponse{}
		resp.Default()
		resp.Version = dr.Version
		resp.ErrorCode = 54 // SECURITY_DISABLED
		msg := "Security features are disabled."
		resp.ErrorMessage = &msg
		return resp, nil, true
	})

	return cluster.ListenAddrs(), cluster.Close
}

func TestExtract_LiveCluster_ACLsNotEnabled(t *testing.T) {
	addrs, closeFn := newFakeSecurityDisabled(t)
	defer closeFn()

	a, err := live.New(addrs, "", nil, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_, _, _, _, err = a.Extract()
	if err == nil {
		t.Fatal("expected an error when the source cluster has ACLs disabled")
	}
	msg := err.Error()
	// The message must name the actual problem (ACLs not enabled / no
	// authorizer) rather than leaking the raw SECURITY_DISABLED code, and
	// should point the operator at the broker configuration to fix.
	for _, want := range []string{"ACLs", "authorizer"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q does not mention %q", msg, want)
		}
	}
}

func TestExtract_LiveCluster_ConnectionFailure(t *testing.T) {
	// 127.0.0.1:1 (TCPMUX) won't speak Kafka; the describe call should
	// fail within the per-call timeout. This test may take up to
	// describeTimeout to fail — accept that; it is the only slow test.
	a, err := live.New([]string{"127.0.0.1:1"}, "", nil, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_, _, _, _, err = a.Extract()
	if err == nil {
		t.Fatal("expected connection error against unreachable broker")
	}
}
