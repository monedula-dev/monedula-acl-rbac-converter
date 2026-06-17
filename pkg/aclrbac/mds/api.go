// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// CreateRoleBinding POSTs a binding to MDS. Returns nil on 2xx, or a typed
// error otherwise.
func CreateRoleBinding(cl *Client, b types.Binding) error {
	body := mdsBindingBody{
		Scope:            scopeToMDS(b.Scope),
		ResourcePatterns: patternsToMDS(b.ResourcePatterns),
	}
	path := fmt.Sprintf("/security/1.0/principals/%s/roles/%s/bindings",
		url.PathEscape(b.Principal), url.PathEscape(b.Role))
	resp, err := cl.Post(path, body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ListBindings returns the role bindings a principal holds at the given scope.
//
// Endpoint and shapes verified empirically against Confluent MDS:
//
//	POST /security/1.0/lookup/rolebindings/principal/{principal}
//	body: the scope object directly, e.g. {"clusters":{"kafka-cluster":"..."}}
//	200:  {"scope":{...},"rolebindings":{"<principal>":{"<role>":[<patterns>]}}}
//
// Each (principal, role) entry aggregates all resource patterns for that role
// binding. The returned bindings carry the queried scope.
func ListBindings(cl *Client, principal string, scope types.Scope) ([]types.Binding, error) {
	path := "/security/1.0/lookup/rolebindings/principal/" + url.PathEscape(principal)
	resp, err := cl.Post(path, scopeToMDS(scope))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var raw struct {
		Rolebindings map[string]map[string][]mdsResourcePattern `json:"rolebindings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("mds: decode rolebindings lookup: %w", err)
	}

	var out []types.Binding
	for prin, roles := range raw.Rolebindings {
		for role, patterns := range roles {
			b := types.Binding{Principal: prin, Role: role, Scope: scope}
			for _, p := range patterns {
				b.ResourcePatterns = append(b.ResourcePatterns, types.ResourcePattern{
					ResourceType: types.ResourceType(p.ResourceType),
					Name:         p.Name,
					PatternType:  types.PatternType(p.PatternType),
				})
			}
			out = append(out, b)
		}
	}
	return out, nil
}

// principalGrant is one effective (operation, resource) grant a principal
// holds, derived by expanding each role binding's resource patterns by the
// operations its role grants on that resource type.
type principalGrant struct {
	op      types.Operation
	rt      types.ResourceType
	name    string
	pattern types.PatternType
}

// fetchPrincipalGrants POSTs the principal's effective role bindings at the
// given scope and expands them into per-operation grants. Verified endpoints:
//
//	POST /security/1.0/lookup/principal/{principal}/resources  (body = scope)
//	  -> {"<principal>":{"<role>":[{resourceType,name,patternType}]}}
//	GET  /security/1.0/roles/{role}  -> accessPolicy.allowedOperations[...]
//
// The lookup response carries no operations (those come from the role
// definition), so each (role, pattern) is expanded by the role's allowed
// operations for that resource type.
func fetchPrincipalGrants(cl *Client, principal string, scope types.Scope) ([]principalGrant, error) {
	path := "/security/1.0/lookup/principal/" + url.PathEscape(principal) + "/resources"
	resp, err := cl.Post(path, scopeToMDS(scope))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// principal -> role -> resource patterns
	var raw map[string]map[string][]mdsResourcePattern
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("mds: decode principal resources lookup: %w", err)
	}

	var out []principalGrant
	for _, roles := range raw {
		for role, patterns := range roles {
			ops, err := cl.roleOps(role)
			if err != nil {
				return nil, err
			}
			for _, p := range patterns {
				rt := types.ResourceType(p.ResourceType)
				for op := range ops[rt] {
					out = append(out, principalGrant{
						op:      op,
						rt:      rt,
						name:    p.Name,
						pattern: types.PatternType(p.PatternType),
					})
				}
			}
		}
	}
	return out, nil
}

// roleOps returns role -> resourceType -> {operation: true}, fetching the
// role definition from MDS and memoizing it on the client.
func (c *Client) roleOps(role string) (map[types.ResourceType]map[types.Operation]bool, error) {
	c.roleOpsMu.Lock()
	if cached, ok := c.roleOpsCache[role]; ok {
		c.roleOpsMu.Unlock()
		return cached, nil
	}
	c.roleOpsMu.Unlock()

	resp, err := c.Get("/security/1.0/roles/" + url.PathEscape(role))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var raw struct {
		AccessPolicy struct {
			AllowedOperations []struct {
				ResourceType string   `json:"resourceType"`
				Operations   []string `json:"operations"`
			} `json:"allowedOperations"`
		} `json:"accessPolicy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("mds: decode role %q: %w", role, err)
	}
	m := map[types.ResourceType]map[types.Operation]bool{}
	for _, ao := range raw.AccessPolicy.AllowedOperations {
		rt := types.ResourceType(ao.ResourceType)
		if m[rt] == nil {
			m[rt] = map[types.Operation]bool{}
		}
		for _, o := range ao.Operations {
			m[rt][types.Operation(o)] = true
		}
	}
	c.roleOpsMu.Lock()
	c.roleOpsCache[role] = m
	c.roleOpsMu.Unlock()
	return m, nil
}

// LookupAllowed asks MDS whether (principal, op, resource, pattern) is
// permitted, using COVERAGE semantics suited to `verify --mode effective`
// (spec §11.2): a grant vouches for the queried resource only if it covers
// it (LITERAL exact, or PREFIXED whose prefix is a prefix of the queried
// name). This is intentionally conservative — it never reports access that
// isn't clearly granted. Returns false + no error when MDS clearly says
// "no"; false + error when the lookup cannot be performed (caller maps to
// EFFECTIVE_UNKNOWN).
//
// NOTE: do NOT use this for DENY-removal safety. "Is the queried resource
// covered" is not "would removing a DENY grant access" — the latter needs
// symmetric set-overlap (PrincipalGrantOverlaps), because a LITERAL grant
// INSIDE a PREFIXED DENY must count as unsafe even though it doesn't cover
// the DENY's whole prefix.
func LookupAllowed(cl *Client, principal string, op types.Operation, rt types.ResourceType, name string, pattern types.PatternType, scope types.Scope) (bool, error) {
	grants, err := fetchPrincipalGrants(cl, principal, scope)
	if err != nil {
		return false, err
	}
	for _, g := range grants {
		if g.rt != rt || g.op != op {
			continue
		}
		if g.pattern != pattern {
			continue
		}
		switch g.pattern {
		case types.PatternLiteral:
			if g.name != name {
				continue
			}
		case types.PatternPrefixed:
			if !strings.HasPrefix(name, g.name) {
				continue
			}
		default:
			// Unknown pattern types from a future MDS version: require exact
			// name match so we never silently accept an unexpected shape.
			if g.name != name {
				continue
			}
		}
		return true, nil
	}
	return false, nil
}

// PrincipalGrantOverlaps reports whether the principal holds ANY grant for
// (op, resourceType) whose resource pattern OVERLAPS the given (name,
// pattern) — i.e. their resource sets intersect. This is the predicate
// DENY-removal safety needs: removing a DENY grants access iff some live
// grant overlaps the denied resource set. Unlike LookupAllowed it does NOT
// require the grant's pattern type to match the DENY's, so a LITERAL grant
// inside a PREFIXED DENY (or a narrower-prefix grant) is correctly detected
// as unsafe. Returns false + error when the lookup cannot be performed.
func PrincipalGrantOverlaps(cl *Client, principal string, op types.Operation, rt types.ResourceType, name string, pattern types.PatternType, scope types.Scope) (bool, error) {
	grants, err := fetchPrincipalGrants(cl, principal, scope)
	if err != nil {
		return false, err
	}
	for _, g := range grants {
		if g.rt != rt || g.op != op {
			continue
		}
		// Treat an unrecognised pattern type conservatively as overlapping
		// (PatternsOverlap returns true for unknown types), so we never
		// remove a DENY on the strength of a shape we don't understand.
		if types.PatternsOverlap(g.pattern, g.name, pattern, name) {
			return true, nil
		}
	}
	return false, nil
}

// The MDS REST API request body uses camelCase keys (resourcePatterns,
// resourceType, patternType); the scope.clusters keys ("kafka-cluster" etc.)
// are hyphenated. Verified empirically against Confluent MDS — a snake_case
// body is rejected with HTTP 400.
type mdsBindingBody struct {
	Scope            mdsScope             `json:"scope"`
	ResourcePatterns []mdsResourcePattern `json:"resourcePatterns"`
}

type mdsScope struct {
	Clusters map[string]string `json:"clusters,omitempty"`
}

type mdsResourcePattern struct {
	ResourceType string `json:"resourceType"`
	Name         string `json:"name"`
	PatternType  string `json:"patternType"`
}

func scopeToMDS(s types.Scope) mdsScope {
	clusters := map[string]string{}
	if s.KafkaCluster != "" {
		clusters["kafka-cluster"] = s.KafkaCluster
	}
	if s.SchemaRegistryCluster != "" {
		clusters["schema-registry-cluster"] = s.SchemaRegistryCluster
	}
	if s.KSQLCluster != "" {
		clusters["ksql-cluster"] = s.KSQLCluster
	}
	if s.ConnectCluster != "" {
		clusters["connect-cluster"] = s.ConnectCluster
	}
	return mdsScope{Clusters: clusters}
}

func patternsToMDS(p []types.ResourcePattern) []mdsResourcePattern {
	out := make([]mdsResourcePattern, 0, len(p))
	for _, rp := range p {
		out = append(out, mdsResourcePattern{
			ResourceType: string(rp.ResourceType),
			Name:         rp.Name,
			PatternType:  string(rp.PatternType),
		})
	}
	return out
}
