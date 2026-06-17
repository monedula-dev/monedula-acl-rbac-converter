// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live

import (
	"testing"
)

// noTopicResourceTypeCount is the number of concrete resource types enumerated
// by buildFilters when no topic filter is provided (Topic, Group, Cluster,
// TransactionalId, DelegationToken).
const noTopicResourceTypeCount = 5

func TestBuildFilters_NoFiltersReturnsFiveBuilders(t *testing.T) {
	got := buildFilters(nil, nil)
	if len(got) != noTopicResourceTypeCount {
		t.Fatalf("got %d builders, want %d (one per resource type)", len(got), noTopicResourceTypeCount)
	}
}

func TestBuildFilters_PrincipalOnly(t *testing.T) {
	got := buildFilters([]string{"User:alice", "User:bob"}, nil)
	want := 2 * noTopicResourceTypeCount
	if len(got) != want {
		t.Errorf("got %d builders, want %d (2 principals × %d resource types)", len(got), want, noTopicResourceTypeCount)
	}
}

func TestBuildFilters_TopicOnly(t *testing.T) {
	got := buildFilters(nil, []string{"orders", "shipments"})
	if len(got) != 2 {
		t.Errorf("got %d builders, want 2 (one per topic)", len(got))
	}
}

func TestBuildFilters_CrossProduct(t *testing.T) {
	got := buildFilters([]string{"User:alice", "User:bob"}, []string{"orders", "shipments"})
	if len(got) != 4 {
		t.Errorf("got %d builders, want 4 (2 principals * 2 topics)", len(got))
	}
}

func TestBuildFilters_ValidatesForDescribe(t *testing.T) {
	// Every builder we return must satisfy ACLBuilder.ValidateDescribe().
	// If not, DescribeACLs would fail before sending. This is the contract
	// the CLI relies on.
	cases := [][2][]string{
		{nil, nil},
		{{"User:alice"}, nil},
		{nil, {"orders"}},
		{{"User:alice", "User:bob"}, {"orders", "shipments"}},
	}
	for i, c := range cases {
		bs := buildFilters(c[0], c[1])
		for j, b := range bs {
			if err := b.ValidateDescribe(); err != nil {
				t.Errorf("case %d builder %d: ValidateDescribe: %v", i, j, err)
			}
		}
	}
}
