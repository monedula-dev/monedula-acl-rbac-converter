// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build integration

package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// contractMDS is the shared in-process MDS substitute for the integration
// suite, implementing the REAL Confluent MDS REST contract (verified
// empirically against cp-server). It replaces the per-test fakes that each
// hard-coded effective grants: because apply creates the role bindings
// through this fake and the lookups echo them back (expanded by role
// definition), a verify round-trip works without per-principal hard-coding.
//
//	POST /security/1.0/principals/{p}/roles/{role}/bindings   (camelCase) -> 204
//	POST /security/1.0/lookup/rolebindings/principal/{p}
//	     -> {"rolebindings":{"{p}":{"{role}":[{resourceType,name,patternType}]}}}
//	POST /security/1.0/lookup/principal/{p}/resources
//	     -> {"{p}":{"{role}":[{resourceType,name,patternType}]}}
//	GET  /security/1.0/roles                  -> []   (capability probe)
//	GET  /security/1.0/roles/{role}           -> {accessPolicy.allowedOperations}
type contractMDS struct {
	mu       sync.Mutex
	created  map[string]int
	bindings []storedBinding
	requests []string
	authSeen []string // Authorization header per /lookup request
	srv      *httptest.Server
}

type storedBinding struct {
	Principal string
	Role      string
	Patterns  []mdsPattern
}

type mdsPattern struct {
	ResourceType string `json:"resourceType"`
	Name         string `json:"name"`
	PatternType  string `json:"patternType"`
}

// roleOps is the subset of the real role catalogue the integration tests
// exercise: a role -> resourceType -> granted operations.
var roleOps = map[string]map[string][]string{
	"DeveloperRead":  {"Topic": {"Read", "Describe"}, "Group": {"Read", "Describe"}},
	"DeveloperWrite": {"Topic": {"Write", "Describe", "Create"}, "TransactionalId": {"Write", "Describe"}},
	"ResourceOwner":  {"Topic": {"Read", "Write", "Create", "Delete", "Alter", "Describe", "DescribeConfigs", "AlterConfigs"}},
}

func parsePrincipalRole(path string) (principal, role string) {
	inner := strings.TrimPrefix(strings.TrimSuffix(path, "/bindings"), "/security/1.0/principals/")
	parts := strings.SplitN(inner, "/roles/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return inner, ""
}

func lookupPrincipal(path string) string {
	p := strings.TrimSuffix(path, "/resources")
	if i := strings.LastIndex(p, "/principal/"); i >= 0 {
		return p[i+len("/principal/"):]
	}
	return ""
}

func (f *contractMDS) rolebindingsFor(principal string) map[string][]mdsPattern {
	roles := map[string][]mdsPattern{}
	for _, b := range f.bindings {
		if b.Principal == principal {
			roles[b.Role] = append(roles[b.Role], b.Patterns...)
		}
	}
	return roles
}

func newContractMDS() *contractMDS {
	f := &contractMDS{created: map[string]int{}}
	mux := http.NewServeMux()

	mux.HandleFunc("/security/1.0/principals/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/bindings") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		principal, role := parsePrincipalRole(r.URL.Path)
		var body struct {
			ResourcePatterns []mdsPattern `json:"resourcePatterns"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.bindings = append(f.bindings, storedBinding{Principal: principal, Role: role, Patterns: body.ResourcePatterns})
		f.created[r.URL.Path]++
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/security/1.0/lookup/rolebindings/principal/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
		principal := lookupPrincipal(r.URL.Path)
		rb := map[string]map[string][]mdsPattern{}
		if roles := f.rolebindingsFor(principal); len(roles) > 0 {
			rb[principal] = roles
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"rolebindings": rb})
	})

	mux.HandleFunc("/security/1.0/lookup/principal/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
		principal := lookupPrincipal(r.URL.Path)
		out := map[string]map[string][]mdsPattern{}
		if roles := f.rolebindingsFor(principal); len(roles) > 0 {
			out[principal] = roles
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	rolesHandler := func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/security/1.0/roles" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		role := strings.TrimPrefix(r.URL.Path, "/security/1.0/roles/")
		type allowedOp struct {
			ResourceType string   `json:"resourceType"`
			Operations   []string `json:"operations"`
		}
		var ops []allowedOp
		for rt, list := range roleOps[role] {
			ops = append(ops, allowedOp{ResourceType: rt, Operations: list})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"name":         role,
			"accessPolicy": map[string]interface{}{"allowedOperations": ops},
		})
	}
	mux.HandleFunc("/security/1.0/roles", rolesHandler)
	mux.HandleFunc("/security/1.0/roles/", rolesHandler)

	f.srv = httptest.NewServer(mux)
	return f
}

// authenticatedLookups returns how many /lookup requests carried a non-empty
// "Bearer ..." Authorization header (used by the DENY round-trip to assert the
// live re-check is authenticated).
func (f *contractMDS) authenticatedLookups() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.authSeen {
		if strings.HasPrefix(a, "Bearer ") {
			n++
		}
	}
	return n
}

func (f *contractMDS) lookupCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.authSeen)
}
