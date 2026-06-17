// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/log"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
)

func TestClient_BearerTokenAdded(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cl, err := mds.NewClient(mds.Config{
		URL:   srv.URL,
		Token: "test-token-xyz",
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	resp, err := cl.Get("/security/1.0/anything")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if gotAuth != "Bearer test-token-xyz" {
		t.Errorf("Authorization: got %q", gotAuth)
	}
}

func TestClient_TLSInsecureSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	if _, err := cl.Get("/"); err == nil {
		t.Errorf("expected TLS error against self-signed cert")
	}

	cl2, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t", InsecureSkipVerify: true})
	resp, err := cl2.Get("/")
	if err != nil {
		t.Errorf("InsecureSkipVerify should bypass cert check; got %v", err)
	}
	if resp != nil {
		resp.Body.Close()
	}
}

func TestClient_4xxReturnsTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	_, err := cl.Get("/")
	if err == nil {
		t.Fatal("expected error")
	}
	if !mds.IsAuthError(err) {
		t.Errorf("403 should be auth error: %v", err)
	}
}

// TestClient_4xxBodyCapped is the S1 regression guard. The auth-token
// exchange in token.go already capped its 4xx body snippet at 256 B so a
// misbehaving MDS that echoed the Authorization header into its error
// response couldn't leak credentials to stderr + the verify.json `detail`
// field on disk. newHTTPError (used by every non-auth call) had no such
// cap and would slurp the full body into HTTPError.Body via io.ReadAll.
// This test feeds a 1 MiB error body and asserts the captured error body
// is capped at 4 KiB + the truncation marker.
func TestClient_4xxBodyCapped(t *testing.T) {
	const bodyLen = 1 << 20 // 1 MiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write(bytes.Repeat([]byte("A"), bodyLen))
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	_, err := cl.Get("/")
	if err == nil {
		t.Fatal("expected error from 500")
	}
	msg := err.Error()
	if len(msg) > 8*1024 {
		t.Errorf("error message should be bounded; got %d bytes (want <8 KiB)", len(msg))
	}
	if !strings.Contains(msg, "...(truncated)") {
		t.Errorf("expected '(truncated)' marker for capped body; got: %s", msg[:min(200, len(msg))])
	}
}

func TestClient_InsecureSkipVerify_PrintsWarning(t *testing.T) {
	var buf bytes.Buffer
	prev := log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	if _, err := mds.NewClient(mds.Config{URL: srv.URL, Token: "t", InsecureSkipVerify: true}); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(strings.ToUpper(output), "WARN") {
		t.Errorf("expected WARN level in output; got %q", output)
	}
	if !strings.Contains(output, "insecure-skip-verify") {
		t.Errorf("warning should name the flag; got %q", output)
	}
}

func TestClient_NoWarningWhenVerifyEnabled(t *testing.T) {
	var buf bytes.Buffer
	prev := log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, _ = mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	if buf.Len() != 0 {
		t.Errorf("no warning expected when verify is enabled; got %q", buf.String())
	}
}

// TestClient_RefreshesTokenOn401 pins that a mid-run 401 triggers one token
// re-resolution via TokenSource and a retry carrying the new bearer. Without
// it a token that expired during a long apply would fail every subsequent
// call with no recovery.
func TestClient_RefreshesTokenOn401(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") == "Bearer old" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	refreshed := 0
	cl, _ := mds.NewClient(mds.Config{
		URL:   srv.URL,
		Token: "old",
		TokenSource: func() (string, error) {
			refreshed++
			return "fresh", nil
		},
	})
	resp, err := cl.Get("/whatever")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if refreshed != 1 {
		t.Errorf("TokenSource should be called exactly once; got %d", refreshed)
	}
	if len(seen) != 2 || seen[0] != "Bearer old" || seen[1] != "Bearer fresh" {
		t.Errorf("expected [Bearer old, Bearer fresh]; got %v", seen)
	}
}
