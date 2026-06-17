// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live

import (
	"github.com/twmb/franz-go/pkg/kadm"
)

// buildFilters expands the (principalFilter × topicFilter) cross product
// into one *kadm.ACLBuilder per cell. Each builder is configured for a
// describe-style query: it matches both Allow and Deny ACLs, any host, any
// operation, on the topic specified (or every concrete resource type if
// topicFilter is empty for that cell).
//
// franz-go's ACLBuilder requires every describe builder to have:
//   - at least one allow- or deny-side principal+host pair (we always set both),
//   - at least one resource filter (a concrete resource type),
//   - at least one operation (kadm.OpAny matches all operations).
//
// The MATCH pattern type on the topic filter is intentional: it lets one
// query catch literal ACLs (exact topic name) and prefixed ACLs whose
// prefix this topic falls under. ACLPatternAny would over-match by
// including completely unrelated prefixed ACLs.
//
// When no topic filter is provided, we enumerate each concrete Kafka resource
// type instead of using ResourceType=ANY. The ANY resource type is not
// supported by all broker implementations (e.g. cp-kafka 7.6 StandardAuthorizer
// silently returns zero results for ResourceType=ANY queries).
//
// Note: kadm uses the empty string "" as the wildcard sentinel for
// Allow/Deny/AllowHosts/DenyHosts when describing — that's what franz-go's
// describe filter semantics expect for "match any principal/host."
func buildFilters(principalFilter, topicFilter []string) []*kadm.ACLBuilder {
	// Normalise empty slices to a single-element sentinel so the
	// cross-product loop produces one cell, not zero, when one dimension
	// is absent.
	principals := principalFilter
	if len(principals) == 0 {
		principals = []string{""}
	}
	topics := topicFilter
	if len(topics) == 0 {
		topics = []string{""}
	}

	var out []*kadm.ACLBuilder
	for _, pr := range principals {
		for _, t := range topics {
			base := func() *kadm.ACLBuilder {
				b := kadm.NewACLs().
					Operations(kadm.OpAny)
				// An empty principal is the wildcard sentinel for describing ACLs:
				// "" means "match any principal". Call Allow()/AllowHosts() with
				// no arguments to set the anyAllow/anyAllowHosts flags instead of
				// passing empty strings, which would be interpreted as a literal
				// principal/host match by some broker implementations.
				if pr == "" {
					b = b.Allow().AllowHosts().Deny().DenyHosts()
				} else {
					b = b.Allow(pr).AllowHosts("*").Deny(pr).DenyHosts("*")
				}
				return b
			}

			if t != "" {
				b := base().Topics(t).ResourcePatternType(kadm.ACLPatternMatch)
				out = append(out, b)
			} else {
				// When no topic filter is set, enumerate all concrete resource
				// types with ACLPatternAny so every ACL type is returned.
				// ResourceType=ANY (1) is not universally supported and cp-kafka's
				// StandardAuthorizer silently ignores it.
				out = append(out,
					base().Topics().ResourcePatternType(kadm.ACLPatternAny),
					base().Groups().ResourcePatternType(kadm.ACLPatternAny),
					base().Clusters().ResourcePatternType(kadm.ACLPatternAny),
					base().TransactionalIDs().ResourcePatternType(kadm.ACLPatternAny),
					base().DelegationTokens().ResourcePatternType(kadm.ACLPatternAny),
				)
			}
		}
	}
	return out
}
