// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan

import (
	"fmt"
	"sort"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/normalize"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Input bundles every value the planner consumes. Pure data — no I/O, no
// file paths. The CLI assembles this from --acls / --rules / --principals /
// --scopes before calling Run.
type Input struct {
	ACLs       types.ACLSet
	Rules      []config.Rule // already merged: defaults + overrides
	Principals config.Principals
	Scopes     types.Scope
	// ExistingBindings is used by the CFK extractor and `mds list-bindings`
	// to mark already-applied bindings as SKIP_EXISTS. Empty for fresh runs.
	ExistingBindings []types.Binding
	// CFKNameSalt is passed through to BindingID; lets users disambiguate from
	// an extremely unlikely hash collision in CFK emit output.
	CFKNameSalt string
	// Now is injected for deterministic tests; defaults to time.Now.
	Now func() time.Time
}

// Run is the planner entry point. It is pure, deterministic, and never
// touches the filesystem or network. Errors mean the input itself is
// unprocessable (e.g., missing kafka_cluster in scope when a Topic binding
// is needed, or principal fallback=fail with an unmapped principal).
func Run(in Input) (types.Plan, error) {
	if in.Now == nil {
		in.Now = time.Now
	}

	groups := normalize.Normalize(in.ACLs.ACLs)

	plan := types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   in.Now().UTC().Format(time.RFC3339),
		Bindings:      []types.Binding{},
		Unmapped:      []types.UnmappedEntry{},
		Rejected:      []types.RejectedEntry{},
		Warnings:      []types.Warning{},
		DenyAnalysis:  []types.DenyAnalysisEntry{},
	}

	warns := &warningCollector{}

	for _, g := range groups {
		switch {
		case g.PermissionType == types.PermissionDeny:
			plan.Rejected = append(plan.Rejected, types.RejectedEntry{
				SourceACLIDs: g.SourceACLIDs,
				Reason:       "DENY_PERMISSION",
				Detail:       fmt.Sprintf("DENY %s on %s:%s for %s", opSetString(g.Operations), g.ResourceType, g.ResourceName, g.Principal),
			})
			continue

		case g.Host != "*":
			plan.Unmapped = append(plan.Unmapped, types.UnmappedEntry{
				SourceACLIDs: g.SourceACLIDs,
				Reason:       "HOST_RESTRICTED",
				Detail:       fmt.Sprintf("host=%s; RBAC has no host-based scoping", g.Host),
			})
			warns.AddF("HOST_RESTRICTED",
				"%d ACL row(s) for %s on %s:%s restricted to host %q — cannot be expressed in RBAC",
				len(g.SourceACLIDs), g.Principal, g.ResourceType, g.ResourceName, g.Host)
			continue
		}

		// Allow path: map principal, find rule, build binding.
		pr, err := MapPrincipal(g.Principal, in.Principals)
		if err != nil {
			return types.Plan{}, fmt.Errorf("principal mapping: %w", err)
		}
		if pr.LooksLikeMTLSDN {
			warns.AddF("MTLS_DN_PASS_THROUGH",
				"%s passed through verbatim; looks like an mTLS DN — likely will not resolve in MDS",
				g.Principal)
		}

		rules := FindCoveringRules(g, in.Rules)
		if len(rules) == 0 {
			plan.Unmapped = append(plan.Unmapped, types.UnmappedEntry{
				SourceACLIDs: g.SourceACLIDs,
				Reason:       "NO_RULE_MATCH",
				Detail:       fmt.Sprintf("no rule covers %s on %s:%s with ops %v", g.PermissionType, g.ResourceType, g.ResourceName, sortedOps(g.Operations)),
			})
			// Special case: a genuinely lone Create on Cluster (Create is the
			// group's only op) with no paired prefixed-topic Allow has no
			// scoped RBAC equivalent → warn. Don't fire when Create is bundled
			// with other ops (not lone) or when the principal also holds a
			// prefixed-topic Allow (the "paired" case the message excludes).
			if g.ResourceType == types.ResourceCluster && len(g.Operations) == 1 &&
				g.Operations[types.OpCreate] && !hasPrefixedTopicAllow(groups, g.Principal) {
				warns.AddF("LONE_CREATE_ON_CLUSTER",
					"Allow Create on Cluster for %s without a paired prefixed-topic ACL — no scoped RBAC equivalent",
					g.Principal)
			}
			continue
		}

		// The selected rules may yield more than one role: a principal holding
		// both Read and Write on a topic needs DeveloperRead AND DeveloperWrite
		// (RBAC is additive). If, even across all selected roles, some operation
		// is still not granted, the conversion is partial — warn rather than
		// silently drop the uncovered grants (e.g. a lone Delete no rule covers).
		if missing := uncoveredOps(g, rules); len(missing) > 0 {
			warns.AddF("PARTIAL_RULE_COVERAGE",
				"role(s) %s for %s on %s:%s do not grant operation(s) %s present in the source ACLs — those grants are not converted",
				rolesJoin(rules), g.Principal, g.ResourceType, g.ResourceName, opsJoin(missing))
		}

		if err := RequireScope(in.Scopes, g.ResourceType); err != nil {
			return types.Plan{}, err
		}

		// Emit one binding per distinct role. Two selected rules can share a
		// role (each covering different ops); they collapse to one binding.
		seenRole := map[string]bool{}
		for _, rule := range rules {
			if seenRole[rule.Then.Role] {
				continue
			}
			seenRole[rule.Then.Role] = true

			binding := types.Binding{
				Action:    types.ActionCreate,
				Principal: pr.Resolved,
				Role:      rule.Then.Role,
				Scope:     ApplyScope(in.Scopes, g.ResourceType),
				ResourcePatterns: []types.ResourcePattern{{
					ResourceType: g.ResourceType,
					Name:         g.ResourceName,
					PatternType:  g.PatternType,
				}},
				SourceACLIDs: g.SourceACLIDs,
			}
			binding.ID = BindingID(binding, in.CFKNameSalt)

			match, existing := classifyAgainstExisting(binding, in.ExistingBindings)
			switch match {
			case existingEquivalent:
				binding.Action = types.ActionSkipExists
				plan.Bindings = append(plan.Bindings, binding)
			case existingSamePrincipalRoleDifferentResources:
				plan.Unmapped = append(plan.Unmapped, types.UnmappedEntry{
					SourceACLIDs: g.SourceACLIDs,
					Reason:       "CONFLICTING_EXISTING_BINDING",
					Detail:       "existing binding: " + describeBinding(*existing),
				})
				warns.AddF("CONFLICTING_EXISTING_BINDING",
					"existing MDS binding for %s as %s on different resources blocks new binding for %v",
					pr.Resolved, rule.Then.Role, g.SourceACLIDs)
			default:
				plan.Bindings = append(plan.Bindings, binding)
			}
		}
	}

	plan.DenyAnalysis = analyzeDenies(groups, in.ACLs.ACLs)
	plan.Warnings = warns.All()
	return plan, nil
}

// hasPrefixedTopicAllow reports whether the principal holds any prefixed-topic
// Allow group — the "paired" companion to a Create-on-Cluster ACL that gives
// it a scoped RBAC equivalent.
func hasPrefixedTopicAllow(groups []normalize.ACLGroup, principal string) bool {
	for _, g := range groups {
		if g.Principal == principal &&
			g.PermissionType == types.PermissionAllow &&
			g.ResourceType == types.ResourceTopic &&
			g.PatternType == types.PatternPrefixed {
			return true
		}
	}
	return false
}

func opSetString(set map[types.Operation]bool) string {
	ops := sortedOps(set)
	if len(ops) == 0 {
		return "<none>"
	}
	s := ""
	for i, op := range ops {
		if i > 0 {
			s += ","
		}
		s += string(op)
	}
	return s
}

// uncoveredOps returns the group's operations that none of the selected rules'
// roles account for. Each rule covers the operations it matched on plus the
// operations those imply under Kafka's authorizer rules (e.g. Read implies
// Describe); a rule matching on `All` covers everything the group holds. The
// `All` marker itself is never reported. With greedy multi-rule selection this
// is normally empty — it only stays non-empty when some operation has no rule
// at all (e.g. a lone Delete on a Topic).
func uncoveredOps(g normalize.ACLGroup, rules []config.Rule) []types.Operation {
	covered := map[types.Operation]bool{}
	for _, rule := range rules {
		for op, ok := range ruleCoveredOps(g, rule) {
			if ok {
				covered[op] = true
			}
		}
	}
	var out []types.Operation
	for op := range g.Operations {
		if op == types.OpAll || covered[op] {
			continue
		}
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// opsJoin renders operations as a comma-separated string for diagnostics.
func opsJoin(ops []types.Operation) string {
	s := ""
	for i, op := range ops {
		if i > 0 {
			s += ","
		}
		s += string(op)
	}
	return s
}

// rolesJoin renders the distinct roles of the selected rules as a
// comma-separated string for diagnostics, in selection order.
func rolesJoin(rules []config.Rule) string {
	seen := map[string]bool{}
	s := ""
	for _, r := range rules {
		if seen[r.Then.Role] {
			continue
		}
		seen[r.Then.Role] = true
		if s != "" {
			s += ","
		}
		s += r.Then.Role
	}
	return s
}

func sortedOps(set map[types.Operation]bool) []types.Operation {
	out := make([]types.Operation, 0, len(set))
	for op := range set {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
